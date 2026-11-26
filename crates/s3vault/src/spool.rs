//! Upload spools: a body is hashed while it arrives and kept in RAM (small) or in an encrypted local file
//! (large, or multipart parts), because the object header (size, MD5, SHA-256) precedes the body.
//! Plaintext never touches the disk: files use the chunk cipher from `s3vault_format::spool`.

use crate::remote::ByteStream;
use crate::streams::window;
use bytes::{Bytes, BytesMut};
use futures::StreamExt;
use md5::{Digest as _, Md5};
use rand::RngCore;
use s3vault_format::object::{CHUNK, ChunkCipher, SEALED_CHUNK};
use s3vault_format::spool::{SALT_LEN, cipher};
use sha2::Sha256;
use std::io;
use std::path::{Path, PathBuf};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use zeroize::Zeroizing;

struct FileW {
    tmp: PathBuf,
    f: tokio::fs::File,
    cipher: ChunkCipher,
    idx: u64,
    buf: BytesMut,
}

pub struct SpoolWriter {
    dir: PathBuf,
    key: Zeroizing<[u8; 32]>,
    max_mem: usize,
    mem: BytesMut,
    file: Option<FileW>,
    final_path: Option<PathBuf>,
    size: u64,
    md5: Md5,
    sha: Sha256,
}

pub struct Spool {
    pub size: u64,
    pub md5: [u8; 16],
    pub sha256: [u8; 32],
    data: Data,
}

enum Data {
    Mem(Bytes),
    File {
        path: PathBuf,
        key: Zeroizing<[u8; 32]>,
        delete: bool,
    },
}

impl Drop for Spool {
    fn drop(&mut self) {
        if let Data::File {
            path, delete: true, ..
        } = &self.data
        {
            let _ = std::fs::remove_file(path);
        }
    }
}

fn rand_name() -> String {
    let mut b = [0u8; 12];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

impl SpoolWriter {
    /// A temporary spool: RAM up to `max_mem`, then an encrypted file in `dir` (deleted on drop).
    pub fn new(dir: &Path, spool_key: &[u8; 32], max_mem: usize) -> Self {
        SpoolWriter {
            dir: dir.to_path_buf(),
            key: Zeroizing::new(*spool_key),
            max_mem,
            mem: BytesMut::new(),
            file: None,
            final_path: None,
            size: 0,
            md5: Md5::new(),
            sha: Sha256::new(),
        }
    }

    /// A persistent spool file at `final_path` (multipart parts); written to a temp name and renamed.
    pub fn persistent(final_path: &Path, spool_key: &[u8; 32]) -> Self {
        let mut w = Self::new(final_path.parent().unwrap_or(Path::new(".")), spool_key, 0);
        w.final_path = Some(final_path.to_path_buf());
        w
    }

    async fn open_file(&mut self) -> io::Result<()> {
        tokio::fs::create_dir_all(&self.dir).await?;
        let tmp = self.dir.join(format!(".spool-{}.tmp", rand_name()));
        let mut f = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)
            .await?;
        let mut salt = [0u8; SALT_LEN];
        rand::rngs::OsRng.fill_bytes(&mut salt);
        f.write_all(&salt).await?;
        let mut fw = FileW {
            tmp,
            f,
            cipher: cipher(&self.key, &salt),
            idx: 0,
            buf: BytesMut::new(),
        };
        let mem = std::mem::take(&mut self.mem);
        fw.push(&mem).await?;
        self.file = Some(fw);
        Ok(())
    }

    pub async fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.size += data.len() as u64;
        self.md5.update(data);
        sha2::Digest::update(&mut self.sha, data);
        if self.file.is_none() && self.mem.len() + data.len() > self.max_mem {
            self.open_file().await?;
        }
        match &mut self.file {
            Some(fw) => fw.push(data).await,
            None => {
                self.mem.extend_from_slice(data);
                Ok(())
            }
        }
    }

    pub async fn finish(mut self) -> io::Result<Spool> {
        if self.final_path.is_some() && self.file.is_none() {
            self.open_file().await?;
        }
        let md5: [u8; 16] = self.md5.finalize_reset().into();
        let sha256: [u8; 32] = sha2::Digest::finalize_reset(&mut self.sha).into();
        let data = match self.file.take() {
            None => Data::Mem(std::mem::take(&mut self.mem).freeze()),
            Some(mut fw) => {
                let last = fw.cipher.seal(fw.idx, true, &fw.buf);
                fw.f.write_all(&last).await?;
                fw.f.sync_data().await?;
                drop(fw.f);
                let (path, delete) = match &self.final_path {
                    Some(p) => {
                        tokio::fs::rename(&fw.tmp, p).await?;
                        (p.clone(), false)
                    }
                    None => (fw.tmp.clone(), true),
                };
                Data::File {
                    path,
                    key: self.key.clone(),
                    delete,
                }
            }
        };
        Ok(Spool {
            size: self.size,
            md5,
            sha256,
            data,
        })
    }
}

impl Drop for SpoolWriter {
    fn drop(&mut self) {
        if let Some(fw) = &self.file {
            let _ = std::fs::remove_file(&fw.tmp);
        }
    }
}

impl FileW {
    async fn push(&mut self, data: &[u8]) -> io::Result<()> {
        self.buf.extend_from_slice(data);
        while self.buf.len() > CHUNK {
            let chunk = self.buf.split_to(CHUNK);
            let sealed = self.cipher.seal(self.idx, false, &chunk);
            self.idx += 1;
            self.f.write_all(&sealed).await?;
        }
        Ok(())
    }
}

impl Spool {
    pub fn from_bytes(b: Bytes) -> Spool {
        let md5: [u8; 16] = Md5::digest(&b).into();
        let sha256: [u8; 32] =
            sha2::Digest::finalize(<Sha256 as sha2::Digest>::new_with_prefix(&b)).into();
        Spool {
            size: b.len() as u64,
            md5,
            sha256,
            data: Data::Mem(b),
        }
    }

    /// Re-open a persistent spool file (a multipart part). Hashes are not known (zero).
    pub fn open_file(path: &Path, spool_key: &[u8; 32], size: u64) -> Spool {
        Spool {
            size,
            md5: [0; 16],
            sha256: [0; 32],
            data: Data::File {
                path: path.to_path_buf(),
                key: Zeroizing::new(*spool_key),
                delete: false,
            },
        }
    }

    pub fn md5_hex(&self) -> String {
        hex::encode(self.md5)
    }

    pub fn sha256_hex(&self) -> String {
        hex::encode(self.sha256)
    }

    pub fn as_bytes(&self) -> Option<&Bytes> {
        match &self.data {
            Data::Mem(b) => Some(b),
            Data::File { .. } => None,
        }
    }

    /// The plaintext as a stream.
    pub fn stream(&self) -> ByteStream {
        match &self.data {
            Data::Mem(b) => {
                let b = b.clone();
                Box::pin(futures::stream::iter(
                    (0..b.len().div_ceil(CHUNK).max(1))
                        .map(move |i| Ok(b.slice(i * CHUNK..((i + 1) * CHUNK).min(b.len())))),
                ))
            }
            Data::File { path, key, .. } => file_stream(path.clone(), key.clone()),
        }
    }

    /// Plaintext bytes `[start, end)`.
    pub fn range_stream(&self, start: u64, end: u64) -> ByteStream {
        match &self.data {
            Data::Mem(b) => {
                let s = b.slice(start as usize..end as usize);
                Box::pin(futures::stream::once(async move { Ok(s) }))
            }
            Data::File { .. } => Box::pin(window(self.stream(), start, end - start)),
        }
    }
}

fn file_stream(path: PathBuf, key: Zeroizing<[u8; 32]>) -> ByteStream {
    let fut = async move {
        let mut f = tokio::fs::File::open(&path).await?;
        let len = f.metadata().await?.len();
        let mut salt = [0u8; SALT_LEN];
        f.read_exact(&mut salt).await?;
        let c = cipher(&key, &salt);
        Ok::<_, io::Error>((f, c, len - SALT_LEN as u64))
    };
    let s = futures::stream::once(fut).flat_map(|r| -> ByteStream {
        match r {
            Err(e) => Box::pin(futures::stream::once(async move { Err(e) })),
            Ok((f, c, remaining)) => Box::pin(futures::stream::unfold(
                (f, c, remaining, 0u64, false),
                |(mut f, c, remaining, idx, done)| async move {
                    if done {
                        return None;
                    }
                    let n = remaining.min(SEALED_CHUNK as u64) as usize;
                    let last = remaining <= SEALED_CHUNK as u64;
                    let mut buf = vec![0u8; n];
                    if let Err(e) = f.read_exact(&mut buf).await {
                        return Some((Err(e), (f, c, 0, idx, true)));
                    }
                    match c.open(idx, last, &buf) {
                        Ok(p) => Some((
                            Ok(Bytes::from(p)),
                            (f, c, remaining - n as u64, idx + 1, last),
                        )),
                        Err(_) => Some((
                            Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                "spool file failed authentication",
                            )),
                            (f, c, 0, idx, true),
                        )),
                    }
                },
            )),
        }
    });
    Box::pin(s)
}

/// Drain a stream into a new spool.
pub async fn spool_stream(mut s: ByteStream, mut w: SpoolWriter) -> io::Result<Spool> {
    while let Some(chunk) = s.next().await {
        w.write(&chunk?).await?;
    }
    w.finish().await
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn collect(mut s: ByteStream) -> Vec<u8> {
        let mut v = Vec::new();
        while let Some(c) = s.next().await {
            v.extend_from_slice(&c.unwrap());
        }
        v
    }

    #[tokio::test]
    async fn mem_and_file_spools() {
        let d = tempfile::tempdir().unwrap();
        for (n, max_mem) in [
            (10usize, 100usize),
            (3 * CHUNK + 5, 1000),
            (2 * CHUNK, 10),
            (0, 0),
        ] {
            let data: Vec<u8> = (0..n).map(|i| (i % 253) as u8).collect();
            let mut w = SpoolWriter::new(d.path(), &[3; 32], max_mem);
            for part in data.chunks(7777) {
                w.write(part).await.unwrap();
            }
            let sp = w.finish().await.unwrap();
            assert_eq!(sp.size as usize, n);
            assert_eq!(
                sp.sha256_hex(),
                hex::encode(<Sha256 as sha2::Digest>::digest(&data))
            );
            assert_eq!(collect(sp.stream()).await, data);
            if n > 10 {
                assert_eq!(
                    collect(sp.range_stream(5, n as u64 - 3)).await,
                    &data[5..n - 3]
                );
            }
        }
        // temp files are removed on drop
        assert_eq!(std::fs::read_dir(d.path()).unwrap().count(), 0);
    }

    #[tokio::test]
    async fn persistent_part_reopen() {
        let d = tempfile::tempdir().unwrap();
        let p = d.path().join("part-1");
        let data = vec![9u8; CHUNK + 3];
        let mut w = SpoolWriter::persistent(&p, &[4; 32]);
        w.write(&data).await.unwrap();
        let sp = w.finish().await.unwrap();
        drop(sp);
        assert!(p.exists());
        let back = Spool::open_file(&p, &[4; 32], data.len() as u64);
        assert_eq!(collect(back.stream()).await, data);
        // the file holds no plaintext run
        let raw = std::fs::read(&p).unwrap();
        assert!(!raw.windows(64).any(|w| w.iter().all(|b| *b == 9)));
    }
}
