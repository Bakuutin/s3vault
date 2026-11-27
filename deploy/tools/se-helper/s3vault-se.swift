// s3vault-se: the Secure Enclave slot helper for macOS (key hierarchy 3.3, the `a` device slot).
//
// The P-256 private key is created inside the Secure Enclave and never leaves it. The key file holds only the
// enclave's wrapped handle (CryptoKit dataRepresentation), usable on this Mac's enclave only. It speaks the slot
// helper protocol of s3vault (crates/s3vault-format/src/slots.rs):
//
//   s3vault-se create FILE [--presence]   new enclave key; FILE (mode 600, refuses to overwrite); prints kem/pk
//                                         --presence: every use needs Touch ID or the login password (production
//                                         device slot, review R1). Without it no prompt ever appears (tests).
//   s3vault-se pub FILE                   prints "kem p256" and "pk <base64 X9.63>"
//   s3vault-se dh FILE                    stdin: base64 of the sender's ephemeral P-256 key (X9.63)
//                                         stdout: base64 of the ECDH x-coordinate (32 bytes)
//
// Build: swiftc -O -o s3vault-se s3vault-se.swift   (no entitlements needed: no keychain item is created)
import CryptoKit
import Foundation
import Security

func die(_ m: String) -> Never {
    FileHandle.standardError.write(("s3vault-se: " + m + "\n").data(using: .utf8)!)
    exit(1)
}

let a = CommandLine.arguments
if a.count < 3 { die("usage: s3vault-se create|pub|dh FILE [--presence]") }
if !SecureEnclave.isAvailable { die("no Secure Enclave on this machine") }
let path = (a[2] as NSString).expandingTildeInPath

func load() -> SecureEnclave.P256.KeyAgreement.PrivateKey {
    guard let d = FileManager.default.contents(atPath: path) else { die("cannot read \(path)") }
    do { return try SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: d) } catch {
        die("not a key of this Secure Enclave: \(error)")
    }
}

func printPub(_ k: SecureEnclave.P256.KeyAgreement.PrivateKey) {
    print("kem p256")
    print("pk \(k.publicKey.x963Representation.base64EncodedString())")
}

switch a[1] {
case "create":
    if FileManager.default.fileExists(atPath: path) { die("\(path) exists (refusing to overwrite)") }
    var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
    if a.contains("--presence") { flags.insert(.userPresence) }
    var err: Unmanaged<CFError>?
    guard let ac = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &err)
    else { die("access control: \(String(describing: err))") }
    let k: SecureEnclave.P256.KeyAgreement.PrivateKey
    do { k = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: ac) } catch { die("create: \(error)") }
    if !FileManager.default.createFile(atPath: path, contents: k.dataRepresentation, attributes: [.posixPermissions: 0o600]) {
        die("cannot write \(path)")
    }
    printPub(k)
case "pub":
    printPub(load())
case "dh":
    let k = load()
    guard let line = readLine(), let raw = Data(base64Encoded: line.trimmingCharacters(in: .whitespaces)) else {
        die("dh: expected one base64 line on stdin")
    }
    do {
        let peer = try P256.KeyAgreement.PublicKey(x963Representation: raw)
        let ss = try k.sharedSecretFromKeyAgreement(with: peer)
        print(ss.withUnsafeBytes { Data($0) }.base64EncodedString())
    } catch { die("dh: \(error)") }
default:
    die("unknown verb \(a[1])")
}
