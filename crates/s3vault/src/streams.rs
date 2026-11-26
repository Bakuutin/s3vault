//! Stream adapters: encrypt a plaintext stream into the object format, decrypt a ranged ciphertext stream,
//! and cut a byte window out of a stream.

use crate::remote::ByteStream;
use bytes::{Bytes, BytesMut};
use futures::{Stream, StreamExt};
use s3vault_format::object::{CHUNK, ChunkCipher, Layout, TAG};
use std::io;

fn invalid(msg: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

/// Skip `skip` bytes, then yield `len` bytes.
pub fn window(
    inner: impl Stream<Item = io::Result<Bytes>> + Send + 'static,
    skip: u64,
    len: u64,
) -> impl Stream<Item = io::Result<Bytes>> + Send {
    let state = (Box::pin(inner), skip, len);
    futures::stream::unfold(state, |(mut inner, mut skip, mut len)| async move {
        loop {
            if len == 0 {
                return None;
            }
            match inner.next().await {
                None => return Some((Err(invalid("stream ended early")), (inner, 0, 0))),
                Some(Err(e)) => return Some((Err(e), (inner, 0, 0))),
                Some(Ok(mut b)) => {
                    if skip >= b.len() as u64 {
                        skip -= b.len() as u64;
                        continue;
                    }
                    let _ = b.split_to(skip as usize);
                    skip = 0;
                    if b.len() as u64 > len {
                        b.truncate(len as usize);
                    }
                    len -= b.len() as u64;
                    return Some((Ok(b), (inner, skip, len)));
                }
            }
        }
    })
}

struct EncState {
    plain: ByteStream,
    buf: BytesMut,
    idx: u64,
    cipher: ChunkCipher,
    layout: Layout,
    prefix: Option<Bytes>,
    done: bool,
}

/// Preamble + sealed header (`prefix`), then the sealed body chunks of `plain` (exactly `layout.size` bytes).
pub fn encrypt_stream(
    prefix: Vec<u8>,
    cipher: ChunkCipher,
    layout: Layout,
    plain: ByteStream,
) -> ByteStream {
    let st = EncState {
        plain,
        buf: BytesMut::new(),
        idx: 0,
        cipher,
        layout,
        prefix: Some(Bytes::from(prefix)),
        done: false,
    };
    Box::pin(futures::stream::unfold(st, |mut st| async move {
        if let Some(p) = st.prefix.take() {
            return Some((Ok(p), st));
        }
        if st.done {
            return None;
        }
        let n = st.layout.chunk_plain_len(st.idx) as usize;
        while st.buf.len() < n {
            match st.plain.next().await {
                Some(Ok(b)) => st.buf.extend_from_slice(&b),
                Some(Err(e)) => {
                    st.done = true;
                    return Some((Err(e), st));
                }
                None => {
                    st.done = true;
                    return Some((Err(invalid("body shorter than its declared size")), st));
                }
            }
        }
        let chunk = st.buf.split_to(n);
        let last = st.layout.is_last(st.idx);
        let sealed = st.cipher.seal(st.idx, last, &chunk);
        st.idx += 1;
        if last {
            st.done = true;
            let mut extra = !st.buf.is_empty();
            while !extra {
                match st.plain.next().await {
                    Some(Ok(b)) if b.is_empty() => continue,
                    Some(Ok(_)) => extra = true,
                    Some(Err(e)) => return Some((Err(e), st)),
                    None => break,
                }
            }
            if extra {
                return Some((Err(invalid("body longer than its declared size")), st));
            }
        }
        Some((Ok(Bytes::from(sealed)), st))
    }))
}

struct DecState {
    ct: ByteStream,
    buf: BytesMut,
    idx: u64,
    last: u64,
    cipher: ChunkCipher,
    layout: Layout,
    start: u64,
    end: u64,
    done: bool,
}

/// Decrypt the ciphertext of chunks `first..=last` and yield plaintext bytes `[start, end)`.
pub fn decrypt_stream(
    ct: ByteStream,
    cipher: ChunkCipher,
    layout: Layout,
    first: u64,
    last: u64,
    start: u64,
    end: u64,
) -> ByteStream {
    let st = DecState {
        ct,
        buf: BytesMut::new(),
        idx: first,
        last,
        cipher,
        layout,
        start,
        end,
        done: false,
    };
    Box::pin(futures::stream::unfold(st, |mut st| async move {
        if st.done || st.idx > st.last {
            return None;
        }
        let need = st.layout.chunk_plain_len(st.idx) as usize + TAG;
        while st.buf.len() < need {
            match st.ct.next().await {
                Some(Ok(b)) => st.buf.extend_from_slice(&b),
                Some(Err(e)) => {
                    st.done = true;
                    return Some((Err(e), st));
                }
                None => {
                    st.done = true;
                    return Some((Err(invalid("stored object shorter than expected")), st));
                }
            }
        }
        let sealed = st.buf.split_to(need);
        let plain = match st.cipher.open(st.idx, st.layout.is_last(st.idx), &sealed) {
            Ok(p) => p,
            Err(_) => {
                st.done = true;
                tracing::error!("integrity: stored chunk failed authentication");
                return Some((
                    Err(invalid("integrity: stored object failed authentication")),
                    st,
                ));
            }
        };
        let cs = st.idx * CHUNK as u64;
        let a = st.start.saturating_sub(cs) as usize;
        let b = ((st.end - cs) as usize).min(plain.len());
        st.idx += 1;
        Some((Ok(Bytes::from(plain).slice(a..b)), st))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use s3vault_format::keyring::Keyring;
    use s3vault_format::object::{self, Header, seal_head};

    async fn collect(mut s: ByteStream) -> io::Result<Vec<u8>> {
        let mut v = Vec::new();
        while let Some(c) = s.next().await {
            v.extend_from_slice(&c?);
        }
        Ok(v)
    }

    fn pieces(data: &[u8], step: usize) -> ByteStream {
        let v: Vec<io::Result<Bytes>> = data
            .chunks(step.max(1))
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        Box::pin(futures::stream::iter(v))
    }

    #[tokio::test]
    async fn encrypt_then_decrypt_ranges() {
        let kr = Keyring::generate();
        for n in [0usize, 5, CHUNK, 2 * CHUNK + 77] {
            let data: Vec<u8> = (0..n).map(|i| (i % 241) as u8).collect();
            let h = Header {
                v: 1,
                bucket: "b".into(),
                key: "k".into(),
                size: n as u64,
                etag: String::new(),
                sha256: String::new(),
                content_type: None,
                meta: Default::default(),
                generation: 1,
                mtime_ms: 0,
                tombstone: false,
            };
            let head = seal_head(&kr, &h).unwrap();
            let layout = Layout {
                header_sealed_len: head.info.header_sealed_len as u64,
                size: n as u64,
            };
            let info = head.info.clone();
            let ct = collect(encrypt_stream(
                head.prefix,
                head.body,
                layout,
                pieces(&data, 1000),
            ))
            .await
            .unwrap();
            assert_eq!(ct.len() as u64, layout.total_len());
            let (h2, _) = object::open_head(&kr, &ct).unwrap();
            assert_eq!(h2, h);
            if n > 0 {
                for (s, e) in [(0u64, n as u64), (n as u64 / 2, n as u64), (0, 1)] {
                    let (f, l) = layout.chunks_for(s, e);
                    let (cs, ce) = layout.ciphertext_span(f, l);
                    let c = object::body_cipher(&kr, &info).unwrap();
                    let got = collect(decrypt_stream(
                        pieces(&ct[cs as usize..=ce as usize], 333),
                        c,
                        layout,
                        f,
                        l,
                        s,
                        e,
                    ))
                    .await
                    .unwrap();
                    assert_eq!(got, &data[s as usize..e as usize]);
                }
            }
            // wrong size is refused
            let head = seal_head(&kr, &h).unwrap();
            let bad = Layout {
                header_sealed_len: head.info.header_sealed_len as u64,
                size: n as u64 + 1,
            };
            assert!(
                collect(encrypt_stream(
                    head.prefix,
                    head.body,
                    bad,
                    pieces(&data, 1000)
                ))
                .await
                .is_err()
            );
        }
    }
}
