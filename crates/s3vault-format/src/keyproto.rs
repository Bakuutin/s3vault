//! Key-service protocol: mutual authentication with a pre-shared key (PSK), fresh nonces from both sides,
//! and the keyring sent encrypted under a per-session key. It runs inside Tailscale (WireGuard), and the
//! server also checks the source address, so this layer is defence in depth: someone who reaches the port
//! without the PSK learns nothing, and a replayed session fails because the server nonce is fresh.
//!
//! ```text
//! C -> S  "S3VKEY01" || cn[32]
//! S -> C  sn[32] || HMAC(psk, "s3vault-keyd/server" || cn || sn)
//! C -> S  HMAC(psk, "s3vault-keyd/client" || cn || sn)
//! S -> C  len u32 BE || XChaCha20-Poly1305(HKDF(psk, cn || sn, "s3vault-keyd/v1/transport"), nonce 0,
//!                                          AD "S3VKEY01", keyring text)
//! ```

use crate::keyring::Key32;
use crate::{FormatError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use data_encoding::BASE64;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha2::Sha256;
use std::io::{Read, Write};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

pub const MAGIC: &[u8; 8] = b"S3VKEY01";
const MAX_PAYLOAD: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("protocol: {0}")]
    Proto(&'static str),
    #[error("peer failed authentication")]
    Auth,
}

pub fn generate_psk_text() -> Zeroizing<String> {
    let mut k = Zeroizing::new([0u8; 32]);
    rand::rngs::OsRng.fill_bytes(&mut *k);
    Zeroizing::new(format!("s3vault-psk v1 {}\n", BASE64.encode(&k[..])))
}

pub fn parse_psk(text: &str) -> Result<Key32> {
    let t = text.trim();
    let b64 = t
        .strip_prefix("s3vault-psk v1 ")
        .ok_or(FormatError::Malformed("psk header"))?;
    let mut raw = BASE64
        .decode(b64.trim().as_bytes())
        .map_err(|_| FormatError::Malformed("psk base64"))?;
    if raw.len() != 32 {
        raw.zeroize();
        return Err(FormatError::Malformed("psk length"));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    k.copy_from_slice(&raw);
    raw.zeroize();
    Ok(k)
}

fn tag(psk: &[u8; 32], label: &[u8], cn: &[u8; 32], sn: &[u8; 32]) -> [u8; 32] {
    let mut m = <Hmac<Sha256> as Mac>::new_from_slice(psk).expect("hmac");
    m.update(label);
    m.update(cn);
    m.update(sn);
    m.finalize().into_bytes().into()
}

fn transport(psk: &[u8; 32], cn: &[u8; 32], sn: &[u8; 32]) -> XChaCha20Poly1305 {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(cn);
    salt[32..].copy_from_slice(sn);
    let hk = Hkdf::<Sha256>::new(Some(&salt), psk);
    let mut k = Zeroizing::new([0u8; 32]);
    hk.expand(b"s3vault-keyd/v1/transport", &mut *k)
        .expect("hkdf");
    XChaCha20Poly1305::new((&*k).into())
}

/// Client side: authenticate the server and receive the payload (the keyring text).
pub fn client_fetch<S: Read + Write>(
    s: &mut S,
    psk: &[u8; 32],
) -> std::result::Result<Zeroizing<Vec<u8>>, ProtoError> {
    let mut cn = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut cn);
    let mut hello = Vec::with_capacity(40);
    hello.extend_from_slice(MAGIC);
    hello.extend_from_slice(&cn);
    s.write_all(&hello)?;
    s.flush()?;
    let mut resp = [0u8; 64];
    s.read_exact(&mut resp)?;
    let sn: [u8; 32] = resp[..32].try_into().unwrap();
    let want = tag(psk, b"s3vault-keyd/server", &cn, &sn);
    if !bool::from(want.ct_eq(&resp[32..])) {
        return Err(ProtoError::Auth);
    }
    s.write_all(&tag(psk, b"s3vault-keyd/client", &cn, &sn))?;
    s.flush()?;
    let mut len = [0u8; 4];
    s.read_exact(&mut len)?;
    let len = u32::from_be_bytes(len) as usize;
    if len > MAX_PAYLOAD + 16 {
        return Err(ProtoError::Proto("payload too large"));
    }
    let mut ct = vec![0u8; len];
    s.read_exact(&mut ct)?;
    let plain = transport(psk, &cn, &sn)
        .decrypt(
            &XNonce::default(),
            Payload {
                msg: &ct,
                aad: MAGIC,
            },
        )
        .map_err(|_| ProtoError::Auth)?;
    Ok(Zeroizing::new(plain))
}

/// Server side: authenticate the client, then send the payload encrypted.
pub fn server_serve<S: Read + Write>(
    s: &mut S,
    psk: &[u8; 32],
    payload: &[u8],
) -> std::result::Result<(), ProtoError> {
    if payload.len() > MAX_PAYLOAD {
        return Err(ProtoError::Proto("payload too large"));
    }
    let mut hello = [0u8; 40];
    s.read_exact(&mut hello)?;
    if &hello[..8] != MAGIC {
        return Err(ProtoError::Proto("bad magic"));
    }
    let cn: [u8; 32] = hello[8..].try_into().unwrap();
    let mut sn = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut sn);
    let mut resp = Vec::with_capacity(64);
    resp.extend_from_slice(&sn);
    resp.extend_from_slice(&tag(psk, b"s3vault-keyd/server", &cn, &sn));
    s.write_all(&resp)?;
    s.flush()?;
    let mut ctag = [0u8; 32];
    s.read_exact(&mut ctag)?;
    let want = tag(psk, b"s3vault-keyd/client", &cn, &sn);
    if !bool::from(want.ct_eq(&ctag)) {
        return Err(ProtoError::Auth);
    }
    let ct = transport(psk, &cn, &sn)
        .encrypt(
            &XNonce::default(),
            Payload {
                msg: payload,
                aad: MAGIC,
            },
        )
        .expect("encrypt");
    s.write_all(&(ct.len() as u32).to_be_bytes())?;
    s.write_all(&ct)?;
    s.flush()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{TcpListener, TcpStream};

    fn run(
        server_psk: [u8; 32],
        client_psk: [u8; 32],
    ) -> (std::result::Result<Zeroizing<Vec<u8>>, ProtoError>, bool) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let h = std::thread::spawn(move || {
            let (mut s, _) = l.accept().unwrap();
            server_serve(&mut s, &server_psk, b"secret keyring").is_ok()
        });
        let mut c = TcpStream::connect(addr).unwrap();
        let r = client_fetch(&mut c, &client_psk);
        drop(c);
        (r, h.join().unwrap())
    }

    #[test]
    fn handshake_ok_and_wrong_psk() {
        let (r, ok) = run([1; 32], [1; 32]);
        assert_eq!(&r.unwrap()[..], b"secret keyring");
        assert!(ok);
        let (r, ok) = run([1; 32], [2; 32]);
        assert!(matches!(r, Err(ProtoError::Auth)));
        assert!(!ok);
    }

    #[test]
    fn psk_text_roundtrip() {
        let t = generate_psk_text();
        assert_eq!(parse_psk(&t).unwrap().len(), 32);
        assert!(parse_psk("garbage").is_err());
    }
}
