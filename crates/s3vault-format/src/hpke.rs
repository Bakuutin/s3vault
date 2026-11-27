//! HPKE (RFC 9180), base mode, single shot: the slot wraps of the keystore (key hierarchy, KH2).
//!
//! Suites: KEM DHKEM(X25519, HKDF-SHA256) (0x0020) or DHKEM(P-256, HKDF-SHA256) (0x0010), KDF HKDF-SHA256
//! (0x0001), AEAD ChaCha20-Poly1305 (0x0003). Only the receiver's Diffie-Hellman step needs the private key,
//! so it sits behind [`SlotSecret`]: a software key in RAM, or a helper program in front of a Secure Enclave
//! or a TPM that computes the shared point and never shows the private key.
//!
//! Implemented here (not with a crate) because the Secure Enclave and the TPM do the DH step themselves;
//! the tests check every suite both ways against the `hpke` crate.

use crate::{FormatError, Result};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroizing;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kem {
    X25519,
    P256,
}

impl Kem {
    pub fn id(self) -> u16 {
        match self {
            Kem::X25519 => 0x0020,
            Kem::P256 => 0x0010,
        }
    }

    pub fn from_id(id: u16) -> Result<Kem> {
        match id {
            0x0020 => Ok(Kem::X25519),
            0x0010 => Ok(Kem::P256),
            _ => Err(FormatError::Malformed("unknown HPKE KEM")),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Kem::X25519 => "x25519",
            Kem::P256 => "p256",
        }
    }

    pub fn from_name(n: &str) -> Result<Kem> {
        match n {
            "x25519" => Ok(Kem::X25519),
            "p256" => Ok(Kem::P256),
            _ => Err(FormatError::Malformed("unknown KEM name (x25519 or p256)")),
        }
    }

    /// Length of a serialised public key (and of `enc`).
    pub fn pk_len(self) -> usize {
        match self {
            Kem::X25519 => 32,
            Kem::P256 => 65,
        }
    }
}

const KDF_HKDF_SHA256: u16 = 0x0001;
const AEAD_CHACHA20POLY1305: u16 = 0x0003;

/// The receiver side of a slot: the public key and the DH step with the sender's ephemeral key.
pub trait SlotSecret {
    fn kem(&self) -> Kem;
    fn public_key(&self) -> Vec<u8>;
    /// `DH(sk, enc)`: the X25519 output or the P-256 x-coordinate (32 bytes).
    fn dh(&self, enc: &[u8]) -> Result<Zeroizing<Vec<u8>>>;
}

fn labeled_extract(suite: &[u8], salt: &[u8], label: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut l = Vec::with_capacity(7 + suite.len() + label.len() + ikm.len());
    l.extend_from_slice(b"HPKE-v1");
    l.extend_from_slice(suite);
    l.extend_from_slice(label);
    l.extend_from_slice(ikm);
    let (prk, _) = Hkdf::<Sha256>::extract(Some(salt), &l);
    zeroize::Zeroize::zeroize(&mut l);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&prk);
    out
}

fn labeled_expand(suite: &[u8], prk: &[u8], label: &[u8], info: &[u8], len: usize) -> Zeroizing<Vec<u8>> {
    let mut l = Vec::new();
    l.extend_from_slice(&(len as u16).to_be_bytes());
    l.extend_from_slice(b"HPKE-v1");
    l.extend_from_slice(suite);
    l.extend_from_slice(label);
    l.extend_from_slice(info);
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("prk length");
    let mut out = Zeroizing::new(vec![0u8; len]);
    hk.expand(&l, &mut out).expect("hkdf length");
    out
}

fn kem_suite(kem: Kem) -> Vec<u8> {
    let mut s = b"KEM".to_vec();
    s.extend_from_slice(&kem.id().to_be_bytes());
    s
}

fn hpke_suite(kem: Kem) -> Vec<u8> {
    let mut s = b"HPKE".to_vec();
    s.extend_from_slice(&kem.id().to_be_bytes());
    s.extend_from_slice(&KDF_HKDF_SHA256.to_be_bytes());
    s.extend_from_slice(&AEAD_CHACHA20POLY1305.to_be_bytes());
    s
}

fn extract_and_expand(kem: Kem, dh: &[u8], enc: &[u8], pk_r: &[u8]) -> Zeroizing<Vec<u8>> {
    let suite = kem_suite(kem);
    let prk = labeled_extract(&suite, b"", b"eae_prk", dh);
    let mut ctx = enc.to_vec();
    ctx.extend_from_slice(pk_r);
    labeled_expand(&suite, &prk[..], b"shared_secret", &ctx, 32)
}

/// (key, base nonce) of the base-mode key schedule.
fn key_schedule(kem: Kem, shared: &[u8], info: &[u8]) -> (Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>) {
    let suite = hpke_suite(kem);
    let psk_id_hash = labeled_extract(&suite, b"", b"psk_id_hash", b"");
    let info_hash = labeled_extract(&suite, b"", b"info_hash", info);
    let mut ctx = vec![0u8]; // mode_base
    ctx.extend_from_slice(&psk_id_hash[..]);
    ctx.extend_from_slice(&info_hash[..]);
    let secret = labeled_extract(&suite, shared, b"secret", b"");
    let key = labeled_expand(&suite, &secret[..], b"key", &ctx, 32);
    let nonce = labeled_expand(&suite, &secret[..], b"base_nonce", &ctx, 12);
    (key, nonce)
}

fn x25519_pk(bytes: &[u8]) -> Result<x25519_dalek::PublicKey> {
    let a: [u8; 32] = bytes
        .try_into()
        .map_err(|_| FormatError::Malformed("x25519 public key length"))?;
    Ok(x25519_dalek::PublicKey::from(a))
}

fn p256_pk(bytes: &[u8]) -> Result<p256::PublicKey> {
    if bytes.len() != 65 || bytes[0] != 4 {
        return Err(FormatError::Malformed("p256 public key must be 65 bytes uncompressed"));
    }
    p256::PublicKey::from_sec1_bytes(bytes).map_err(|_| FormatError::Malformed("p256 public key not on the curve"))
}

/// Check a serialised public key for this KEM.
pub fn validate_public_key(kem: Kem, pk: &[u8]) -> Result<()> {
    match kem {
        Kem::X25519 => {
            let p = x25519_pk(pk)?;
            if p.as_bytes().iter().all(|b| *b == 0) {
                return Err(FormatError::Malformed("x25519 public key is zero"));
            }
            Ok(())
        }
        Kem::P256 => p256_pk(pk).map(|_| ()),
    }
}

/// Base-mode single-shot seal to `pk_r`. Returns (enc, ciphertext).
pub fn seal(kem: Kem, pk_r: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
    validate_public_key(kem, pk_r)?;
    let (enc, dh): (Vec<u8>, Zeroizing<Vec<u8>>) = match kem {
        Kem::X25519 => {
            let sk = x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng);
            let pk = x25519_dalek::PublicKey::from(&sk);
            let ss = sk.diffie_hellman(&x25519_pk(pk_r)?);
            if !ss.was_contributory() {
                return Err(FormatError::Malformed("x25519: low-order public key"));
            }
            (pk.as_bytes().to_vec(), Zeroizing::new(ss.as_bytes().to_vec()))
        }
        Kem::P256 => {
            let sk = p256::ecdh::EphemeralSecret::random(&mut rand::rngs::OsRng);
            let pk = p256::EncodedPoint::from(sk.public_key());
            let pk_e = pk.to_bytes().to_vec();
            let ss = sk.diffie_hellman(&p256_pk(pk_r)?);
            (pk_e, Zeroizing::new(ss.raw_secret_bytes().to_vec()))
        }
    };
    let shared = extract_and_expand(kem, &dh, &enc, pk_r);
    let (key, nonce) = key_schedule(kem, &shared, info);
    let ct = ChaCha20Poly1305::new_from_slice(&key)
        .expect("key length")
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: pt, aad })
        .map_err(|_| FormatError::Auth)?;
    Ok((enc, ct))
}

/// Base-mode single-shot open with a slot secret.
pub fn open(sk: &dyn SlotSecret, enc: &[u8], info: &[u8], aad: &[u8], ct: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    let kem = sk.kem();
    validate_public_key(kem, enc)?;
    let dh = sk.dh(enc)?;
    let pk_r = sk.public_key();
    let shared = extract_and_expand(kem, &dh, enc, &pk_r);
    let (key, nonce) = key_schedule(kem, &shared, info);
    ChaCha20Poly1305::new_from_slice(&key)
        .expect("key length")
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: ct, aad })
        .map(Zeroizing::new)
        .map_err(|_| FormatError::Auth)
}

/// A software slot key held in RAM (host slot file, Bitwarden recovery slot, tests, the TPM stand-in).
pub enum SoftSecret {
    X25519(x25519_dalek::StaticSecret),
    P256(p256::SecretKey),
}

impl SoftSecret {
    pub fn generate(kem: Kem) -> SoftSecret {
        match kem {
            Kem::X25519 => SoftSecret::X25519(x25519_dalek::StaticSecret::random_from_rng(rand::rngs::OsRng)),
            Kem::P256 => SoftSecret::P256(p256::SecretKey::random(&mut rand::rngs::OsRng)),
        }
    }

    /// The 32 secret bytes (X25519 scalar or P-256 scalar). Key material: keep in the `Zeroizing`.
    pub fn to_bytes(&self) -> Zeroizing<Vec<u8>> {
        match self {
            SoftSecret::X25519(s) => Zeroizing::new(s.to_bytes().to_vec()),
            SoftSecret::P256(s) => Zeroizing::new(s.to_bytes().to_vec()),
        }
    }

    pub fn from_bytes(kem: Kem, b: &[u8]) -> Result<SoftSecret> {
        match kem {
            Kem::X25519 => {
                let mut a: [u8; 32] = b
                    .try_into()
                    .map_err(|_| FormatError::Malformed("x25519 secret length"))?;
                let s = x25519_dalek::StaticSecret::from(a);
                zeroize::Zeroize::zeroize(&mut a);
                Ok(SoftSecret::X25519(s))
            }
            Kem::P256 => p256::SecretKey::from_slice(b)
                .map(SoftSecret::P256)
                .map_err(|_| FormatError::Malformed("p256 secret")),
        }
    }
}

impl SlotSecret for SoftSecret {
    fn kem(&self) -> Kem {
        match self {
            SoftSecret::X25519(_) => Kem::X25519,
            SoftSecret::P256(_) => Kem::P256,
        }
    }

    fn public_key(&self) -> Vec<u8> {
        match self {
            SoftSecret::X25519(s) => x25519_dalek::PublicKey::from(s).as_bytes().to_vec(),
            SoftSecret::P256(s) => p256::EncodedPoint::from(s.public_key()).to_bytes().to_vec(),
        }
    }

    fn dh(&self, enc: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        match self {
            SoftSecret::X25519(s) => {
                let ss = s.diffie_hellman(&x25519_pk(enc)?);
                if !ss.was_contributory() {
                    return Err(FormatError::Malformed("x25519: low-order public key"));
                }
                Ok(Zeroizing::new(ss.as_bytes().to_vec()))
            }
            SoftSecret::P256(s) => {
                let ss = p256::ecdh::diffie_hellman(s.to_nonzero_scalar(), p256_pk(enc)?.as_affine());
                Ok(Zeroizing::new(ss.raw_secret_bytes().to_vec()))
            }
        }
    }
}

/// Random bytes (keys, ids, nonces).
pub fn random<const N: usize>() -> [u8; N] {
    let mut b = [0u8; N];
    rand::rngs::OsRng.fill_bytes(&mut b);
    b
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{Deserializable, Serializable};

    type Aead = hpke::aead::ChaCha20Poly1305;
    type Kdf = hpke::kdf::HkdfSha256;

    fn crate_seal<K: hpke::Kem>(pk: &[u8], info: &[u8], aad: &[u8], pt: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let pk = K::PublicKey::from_bytes(pk).unwrap();
        let mut rng = rand_core_compat();
        let (enc, ct) = hpke::single_shot_seal::<Aead, Kdf, K, _>(
            &hpke::OpModeS::Base,
            &pk,
            info,
            pt,
            aad,
            &mut rng,
        )
        .unwrap();
        (enc.to_bytes().to_vec(), ct)
    }

    fn rand_core_compat() -> rand::rngs::StdRng {
        use rand::SeedableRng;
        rand::rngs::StdRng::from_entropy()
    }

    #[test]
    fn roundtrip_both_kems_and_binding() {
        for kem in [Kem::X25519, Kem::P256] {
            let sk = SoftSecret::generate(kem);
            let pk = sk.public_key();
            assert_eq!(pk.len(), kem.pk_len());
            let (enc, ct) = seal(kem, &pk, b"info", b"aad", b"unlock key 32 bytes.............").unwrap();
            assert_eq!(enc.len(), kem.pk_len());
            let pt = open(&sk, &enc, b"info", b"aad", &ct).unwrap();
            assert_eq!(&pt[..], b"unlock key 32 bytes.............");
            assert!(open(&sk, &enc, b"other info", b"aad", &ct).is_err(), "info is bound");
            assert!(open(&sk, &enc, b"info", b"x", &ct).is_err(), "aad is bound");
            let other = SoftSecret::generate(kem);
            assert!(open(&other, &enc, b"info", b"aad", &ct).is_err(), "another key");
            let back = SoftSecret::from_bytes(kem, &sk.to_bytes()).unwrap();
            assert_eq!(back.public_key(), pk);
        }
    }

    #[test]
    fn interop_with_the_hpke_crate() {
        // X25519: the crate seals, we open; we seal, the crate opens.
        let sk = SoftSecret::generate(Kem::X25519);
        let (enc, ct) = crate_seal::<hpke::kem::X25519HkdfSha256>(&sk.public_key(), b"i", b"a", b"hello");
        assert_eq!(&open(&sk, &enc, b"i", b"a", &ct).unwrap()[..], b"hello");
        let (enc, ct) = seal(Kem::X25519, &sk.public_key(), b"i", b"a", b"world").unwrap();
        let csk = <hpke::kem::X25519HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&sk.to_bytes()).unwrap();
        let cenc = <hpke::kem::X25519HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&enc).unwrap();
        let pt = hpke::single_shot_open::<Aead, Kdf, hpke::kem::X25519HkdfSha256>(
            &hpke::OpModeR::Base,
            &csk,
            &cenc,
            b"i",
            &ct,
            b"a",
        )
        .unwrap();
        assert_eq!(pt, b"world");
        // P-256 both ways
        let sk = SoftSecret::generate(Kem::P256);
        let (enc, ct) = crate_seal::<hpke::kem::DhP256HkdfSha256>(&sk.public_key(), b"i", b"a", b"hello");
        assert_eq!(&open(&sk, &enc, b"i", b"a", &ct).unwrap()[..], b"hello");
        let (enc, ct) = seal(Kem::P256, &sk.public_key(), b"i", b"a", b"world").unwrap();
        let csk = <hpke::kem::DhP256HkdfSha256 as hpke::Kem>::PrivateKey::from_bytes(&sk.to_bytes()).unwrap();
        let cenc = <hpke::kem::DhP256HkdfSha256 as hpke::Kem>::EncappedKey::from_bytes(&enc).unwrap();
        let pt = hpke::single_shot_open::<Aead, Kdf, hpke::kem::DhP256HkdfSha256>(
            &hpke::OpModeR::Base,
            &csk,
            &cenc,
            b"i",
            &ct,
            b"a",
        )
        .unwrap();
        assert_eq!(pt, b"world");
    }

    #[test]
    fn rejects_bad_public_keys() {
        assert!(seal(Kem::X25519, &[0u8; 32], b"", b"", b"x").is_err());
        assert!(seal(Kem::P256, &[4u8; 65], b"", b"", b"x").is_err());
        assert!(seal(Kem::P256, &[0u8; 33], b"", b"", b"x").is_err());
    }
}
