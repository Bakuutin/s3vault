//! Test environment only (key hierarchy rehearsal): write a format v1 object sealed under the legacy v1 keys carried by a
//! master keyring v2, as a v1 proxy would have stored it. Prints the store name (without the store prefix).
//!   cargo run -p s3vault-format --example kh_v1_object -- MASTER_KEYRING BUCKET KEY PLAIN_FILE OUT_FILE
use s3vault_format::keys2::MasterV2;
use s3vault_format::object::{Header, seal_all, store_name};
use sha2::{Digest, Sha256};

fn main() {
    let a: Vec<String> = std::env::args().collect();
    let m = MasterV2::parse(&std::fs::read_to_string(&a[1]).unwrap()).unwrap();
    let kr = m.legacy.as_ref().expect("the master keyring carries no legacy v1 keys");
    let plain = std::fs::read(&a[4]).unwrap();
    let h = Header {
        v: 1,
        bucket: a[2].clone(),
        key: a[3].clone(),
        size: plain.len() as u64,
        etag: hex::encode(md5_of(&plain)),
        sha256: hex::encode(Sha256::digest(&plain)),
        content_type: None,
        meta: Default::default(),
        generation: 1,
        mtime_ms: 0,
        tombstone: false,
    };
    let (obj, _) = seal_all(kr, &h, &plain).unwrap();
    std::fs::write(&a[5], obj).unwrap();
    println!("{}", store_name(&kr.name_key(), &a[2], &a[3]));
}

fn md5_of(b: &[u8]) -> [u8; 16] {
    // not a real MD5 (no md-5 dependency in this crate); the ETag is not checked by the rehearsal
    let d = Sha256::digest(b);
    d[..16].try_into().unwrap()
}
