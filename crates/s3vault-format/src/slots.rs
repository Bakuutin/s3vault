//! Keystore slots: who can open the keystore (key hierarchy 3.3).
//!
//! A slot holder creates a key pair where the private half will live and hands over only the public half, as a
//! **slot public file**:
//!
//! ```text
//! s3vault-slot-pub v1
//! kem x25519|p256
//! pk <base64>
//! kind host|device|recovery|tenant-device
//! label <one word>
//! holder <one word>
//! backend <one word: file, se, tpm, bitwarden, soft-helper, ...>
//! target master | tenant <name>
//! ```
//!
//! The private half is opened through a **slot descriptor**:
//!
//! * `file:PATH`: a software slot key file (`s3vault-slot-key v1`, `kem`, `sk <base64>`), mode 600. The key host
//!   slot during the migration, the Bitwarden recovery slot (the file is a block in the note), tests.
//! * `helper:REF:PROGRAM [ARGS...]`: a helper program in front of hardware that keeps the private key. The
//!   protocol is `PROGRAM ARGS pub REF` (stdout `kem <name>` and `pk <base64>`) and `PROGRAM ARGS dh REF` (stdin
//!   one base64 line, the sender's ephemeral public key; stdout one base64 line, the DH output). The Secure
//!   Enclave helper on macOS (`s3vault-se`), a TPM helper on Linux, and the software stand-in
//!   `s3vault-keyd slot-helper-soft` (test environment) all speak it, so the keystore code is the same on every
//!   platform (principle 2).

use crate::hpke::{Kem, SlotSecret, SoftSecret};
use crate::{FormatError, Result};
use data_encoding::BASE64;
use sha2::{Digest, Sha256};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use zeroize::Zeroizing;

pub const SLOT_KEY_HEADER: &str = "s3vault-slot-key v1";
pub const SLOT_PUB_HEADER: &str = "s3vault-slot-pub v1";

fn serr(m: impl Into<String>) -> FormatError {
    FormatError::Keyring(format!("slot: {}", m.into()))
}

/// The slot kinds that may be issued. `password` exists in the design but is not issued (KH7).
pub const SLOT_KINDS: &[&str] = &["host", "device", "recovery", "tenant-device"];

fn one_word(v: &str, what: &str) -> Result<String> {
    if v.is_empty() || v.len() > 64 || !v.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(serr(format!("{what} must be one word of 1-64 printable characters")));
    }
    Ok(v.to_string())
}

/// Stable slot id: derived from the public key, so the holder finds its slot without opening anything.
pub fn slot_id(kem: Kem, pk: &[u8]) -> [u8; 8] {
    let mut h = Sha256::new();
    h.update(b"s3vault/keystore/v1/slot-id");
    h.update(kem.id().to_be_bytes());
    h.update(pk);
    h.finalize()[..8].try_into().unwrap()
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PubTarget {
    Master,
    /// A tenant slot (unwraps one TUK). Not issued by default (KH7).
    Tenant(String),
}

#[derive(Debug, Clone)]
pub struct SlotPub {
    pub kem: Kem,
    pub pk: Vec<u8>,
    pub kind: String,
    pub label: String,
    pub holder: String,
    pub backend: String,
    pub target: PubTarget,
}

impl SlotPub {
    pub fn id(&self) -> [u8; 8] {
        slot_id(self.kem, &self.pk)
    }

    pub fn parse(text: &str) -> Result<SlotPub> {
        let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
        if lines.next() != Some(SLOT_PUB_HEADER) {
            return Err(serr("missing 's3vault-slot-pub v1' header"));
        }
        let (mut kem, mut pk, mut kind, mut label, mut holder, mut backend) = (None, None, None, None, None, None);
        let mut target = PubTarget::Master;
        for l in lines {
            let p: Vec<&str> = l.split_whitespace().collect();
            match p.as_slice() {
                ["kem", k] => kem = Some(Kem::from_name(k)?),
                ["pk", b] => pk = Some(BASE64.decode(b.as_bytes()).map_err(|_| serr("bad pk base64"))?),
                ["kind", k] => kind = Some(k.to_string()),
                ["label", v] => label = Some(one_word(v, "label")?),
                ["holder", v] => holder = Some(one_word(v, "holder")?),
                ["backend", v] => backend = Some(one_word(v, "backend")?),
                ["target", "master"] => target = PubTarget::Master,
                ["target", "tenant", n] => target = PubTarget::Tenant(n.to_string()),
                _ => return Err(serr(format!("unrecognised line in slot public file: {}", p.first().unwrap_or(&"")))),
            }
        }
        let kem = kem.ok_or_else(|| serr("missing kem"))?;
        let pk = pk.ok_or_else(|| serr("missing pk"))?;
        crate::hpke::validate_public_key(kem, &pk)?;
        let kind = kind.ok_or_else(|| serr("missing kind"))?;
        if !SLOT_KINDS.contains(&kind.as_str()) {
            return Err(serr(format!("slot kind {kind} is not issued (allowed: {SLOT_KINDS:?})")));
        }
        Ok(SlotPub {
            kem,
            pk,
            kind,
            label: label.ok_or_else(|| serr("missing label"))?,
            holder: holder.unwrap_or_else(|| "owner".into()),
            backend: backend.unwrap_or_else(|| "file".into()),
            target,
        })
    }

    pub fn to_text(&self) -> String {
        let target = match &self.target {
            PubTarget::Master => "master".to_string(),
            PubTarget::Tenant(n) => format!("tenant {n}"),
        };
        format!(
            "{SLOT_PUB_HEADER}\nkem {}\npk {}\nkind {}\nlabel {}\nholder {}\nbackend {}\ntarget {target}\n",
            self.kem.name(),
            BASE64.encode(&self.pk),
            self.kind,
            self.label,
            self.holder,
            self.backend
        )
    }
}

/// A software slot key file (text). Holds key material: keep it in the `Zeroizing`.
pub fn soft_key_text(sk: &SoftSecret) -> Zeroizing<String> {
    let b = sk.to_bytes();
    Zeroizing::new(format!("{SLOT_KEY_HEADER}\nkem {}\nsk {}\n", sk.kem().name(), BASE64.encode(&b)))
}

pub fn parse_soft_key(text: &str) -> Result<SoftSecret> {
    let mut lines = text.lines().map(str::trim).filter(|l| !l.is_empty() && !l.starts_with('#'));
    if lines.next() != Some(SLOT_KEY_HEADER) {
        return Err(serr("missing 's3vault-slot-key v1' header"));
    }
    let mut kem = None;
    let mut sk = None;
    for l in lines {
        let p: Vec<&str> = l.split_whitespace().collect();
        match p.as_slice() {
            ["kem", k] => kem = Some(Kem::from_name(k)?),
            ["sk", b] => sk = Some(Zeroizing::new(BASE64.decode(b.as_bytes()).map_err(|_| serr("bad sk"))?)),
            _ => return Err(serr("unrecognised line in slot key file")),
        }
    }
    SoftSecret::from_bytes(kem.ok_or_else(|| serr("missing kem"))?, &sk.ok_or_else(|| serr("missing sk"))?)
}

/// A slot secret behind a helper program (Secure Enclave, TPM, or the test environment stand-in).
pub struct HelperSecret {
    program: Vec<String>,
    reference: String,
    kem: Kem,
    pk: Vec<u8>,
}

impl HelperSecret {
    pub fn new(reference: &str, program: &[String]) -> Result<HelperSecret> {
        if program.is_empty() {
            return Err(serr("helper: no program"));
        }
        let out = run_helper(program, "pub", reference, None)?;
        let (mut kem, mut pk) = (None, None);
        for l in out.lines() {
            let p: Vec<&str> = l.split_whitespace().collect();
            match p.as_slice() {
                ["kem", k] => kem = Some(Kem::from_name(k)?),
                ["pk", b] => pk = Some(BASE64.decode(b.as_bytes()).map_err(|_| serr("helper: bad pk"))?),
                _ => {}
            }
        }
        let kem = kem.ok_or_else(|| serr("helper: no kem in 'pub' output"))?;
        let pk = pk.ok_or_else(|| serr("helper: no pk in 'pub' output"))?;
        crate::hpke::validate_public_key(kem, &pk)?;
        Ok(HelperSecret { program: program.to_vec(), reference: reference.to_string(), kem, pk })
    }
}

fn run_helper(program: &[String], verb: &str, reference: &str, stdin: Option<&str>) -> Result<Zeroizing<String>> {
    let mut c = Command::new(&program[0]);
    c.args(&program[1..]).arg(verb).arg(reference);
    c.stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = c.spawn().map_err(|e| serr(format!("helper {}: {e}", program[0])))?;
    if let Some(s) = stdin {
        let mut i = child.stdin.take().unwrap();
        i.write_all(s.as_bytes()).map_err(|e| serr(format!("helper stdin: {e}")))?;
    }
    let out = child.wait_with_output().map_err(|e| serr(format!("helper: {e}")))?;
    if !out.status.success() {
        return Err(serr(format!("helper {} {verb} failed ({})", program[0], out.status)));
    }
    String::from_utf8(out.stdout).map(Zeroizing::new).map_err(|_| serr("helper: output not UTF-8"))
}

impl SlotSecret for HelperSecret {
    fn kem(&self) -> Kem {
        self.kem
    }
    fn public_key(&self) -> Vec<u8> {
        self.pk.clone()
    }
    fn dh(&self, enc: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        let out = run_helper(&self.program, "dh", &self.reference, Some(&format!("{}\n", BASE64.encode(enc))))?;
        let dh = Zeroizing::new(BASE64.decode(out.trim().as_bytes()).map_err(|_| serr("helper: bad dh output"))?);
        if dh.len() != 32 {
            return Err(serr("helper: dh output must be 32 bytes"));
        }
        Ok(dh)
    }
}

/// Open the private half of a slot from a descriptor (`file:PATH` or `helper:REF:PROGRAM [ARGS]`).
pub fn open_descriptor(desc: &str) -> Result<Box<dyn SlotSecret>> {
    if let Some(p) = desc.strip_prefix("file:") {
        let text = Zeroizing::new(
            std::fs::read_to_string(expand_home(p)).map_err(|e| serr(format!("read slot key {p}: {e}")))?,
        );
        return Ok(Box::new(parse_soft_key(&text)?));
    }
    if let Some(rest) = desc.strip_prefix("helper:") {
        let (reference, prog) = rest.split_once(':').ok_or_else(|| serr("helper descriptor is helper:REF:PROGRAM"))?;
        let program: Vec<String> = prog.split_whitespace().map(String::from).collect();
        return Ok(Box::new(HelperSecret::new(&expand_home(reference).to_string_lossy(), &program)?));
    }
    Err(serr("slot descriptor must start with file: or helper:"))
}

pub fn expand_home(p: &str) -> PathBuf {
    if let Some(r) = p.strip_prefix("~/") {
        if let Some(h) = std::env::var_os("HOME") {
            return Path::new(&h).join(r);
        }
    }
    PathBuf::from(p)
}

/// The software stand-in for a hardware helper (test environment TPM stand-in): `pub FILE` and `dh FILE` over a
/// software slot key file. Returns the text to print on stdout.
pub fn soft_helper(verb: &str, file: &Path, stdin: &str) -> Result<Zeroizing<String>> {
    let text = Zeroizing::new(std::fs::read_to_string(file).map_err(|e| serr(format!("read {}: {e}", file.display())))?);
    let sk = parse_soft_key(&text)?;
    match verb {
        "pub" => Ok(Zeroizing::new(format!("kem {}\npk {}\n", sk.kem().name(), BASE64.encode(&sk.public_key())))),
        "dh" => {
            let enc = BASE64.decode(stdin.trim().as_bytes()).map_err(|_| serr("dh: bad base64 on stdin"))?;
            let dh = sk.dh(&enc)?;
            Ok(Zeroizing::new(format!("{}\n", BASE64.encode(&dh))))
        }
        _ => Err(serr("verb must be pub or dh")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pub_and_key_files_roundtrip() {
        let sk = SoftSecret::generate(Kem::X25519);
        let text = soft_key_text(&sk);
        let back = parse_soft_key(&text).unwrap();
        assert_eq!(back.public_key(), sk.public_key());
        let p = SlotPub {
            kem: Kem::X25519,
            pk: sk.public_key(),
            kind: "recovery".into(),
            label: "bitwarden-recovery".into(),
            holder: "owner".into(),
            backend: "bitwarden".into(),
            target: PubTarget::Master,
        };
        let q = SlotPub::parse(&p.to_text()).unwrap();
        assert_eq!(q.id(), p.id());
        assert_eq!(q.kind, "recovery");
        assert!(SlotPub::parse(&p.to_text().replace("kind recovery", "kind password")).is_err(), "KH7");
        assert!(SlotPub::parse(&p.to_text().replace("label bitwarden-recovery", "label two words")).is_err());
    }

    /// Real Secure Enclave (macOS): opt-in, never prompts (the test key has no user-presence flag).
    /// `S3VAULT_SE_HELPER=/path/to/s3vault-se cargo test -p s3vault-format -- --ignored secure_enclave`
    #[test]
    #[ignore]
    fn secure_enclave_helper_roundtrip() {
        let Ok(helper) = std::env::var("S3VAULT_SE_HELPER") else { return };
        let d = std::env::temp_dir().join(format!("se-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&d).unwrap();
        let key = d.join("device.se");
        let st = std::process::Command::new(&helper).arg("create").arg(&key).output().unwrap();
        assert!(st.status.success(), "create failed");
        let s = open_descriptor(&format!("helper:{}:{helper}", key.display())).unwrap();
        assert_eq!(s.kem(), Kem::P256);
        let (enc, ct) = crate::hpke::seal(Kem::P256, &s.public_key(), b"i", b"a", b"muk").unwrap();
        assert_eq!(&crate::hpke::open(s.as_ref(), &enc, b"i", b"a", &ct).unwrap()[..], b"muk");
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn soft_helper_stands_in_for_hardware() {
        // the helper protocol through the software stand-in, as the TPM stand-in in test environment uses it
        let sk = SoftSecret::generate(Kem::P256);
        let d = std::env::temp_dir().join(format!("sh-{}", rand::random::<u64>()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("k");
        std::fs::write(&f, soft_key_text(&sk).as_bytes()).unwrap();
        let out = soft_helper("pub", &f, "").unwrap();
        assert!(out.contains(&BASE64.encode(&sk.public_key())));
        let (enc, ct) = crate::hpke::seal(Kem::P256, &sk.public_key(), b"i", b"", b"x").unwrap();
        let dh = soft_helper("dh", &f, &BASE64.encode(&enc)).unwrap();
        assert_eq!(BASE64.decode(dh.trim().as_bytes()).unwrap(), sk.dh(&enc).unwrap().to_vec());
        let _ = ct;
        std::fs::remove_dir_all(&d).unwrap();
    }
}
