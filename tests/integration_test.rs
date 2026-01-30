use isotope::crypto::Identity;
use isotope::protocol::{IsotopePacket, WireMessage};
use isotope::vault::Vault;
use isotope::{PLAINTEXT_SIZE};
use std::fs;
use chrono::Utc;

#[test]
fn test_identity_dual_slot() {
    let path = "test_identity.id";
    if std::path::Path::new(path).exists() {
        fs::remove_file(path).unwrap();
    }

    let pass_ops = "ops_password";
    let pass_casual = "casual_password";

    // Setup
    Identity::setup_dual(path, pass_ops, pass_casual).expect("Setup failed");

    // Load Ops
    let id_ops = Identity::load(path, pass_ops).expect("Failed to load Ops");
    assert_eq!(id_ops.profile_type, "ops");

    // Load Casual
    let id_casual = Identity::load(path, pass_casual).expect("Failed to load Casual");
    assert_eq!(id_casual.profile_type, "casual");

    // Invalid Password
    let err = Identity::load(path, "wrong").err();
    assert!(err.is_some());

    fs::remove_file(path).unwrap();
}

#[test]
fn test_packet_serialization() {
    let msg = WireMessage::Chat {
        sender: "Alice".to_string(),
        content: "Hello World".to_string(),
        timestamp: Utc::now(),
    };

    let data = bincode::serialize(&msg).unwrap();
    let packet = IsotopePacket::new(&data).unwrap();
    
    // Wire format check
    let wire_bytes = packet.to_bytes().unwrap();
    assert_eq!(wire_bytes.len(), PLAINTEXT_SIZE); // Should be padded

    // Roundtrip
    let restored = IsotopePacket::from_bytes(&wire_bytes).unwrap();
    let restored_msg: WireMessage = bincode::deserialize(&restored.payload).unwrap();

    if let WireMessage::Chat { sender, content, .. } = restored_msg {
        assert_eq!(sender, "Alice");
        assert_eq!(content, "Hello World");
    } else {
        panic!("Wrong message type");
    }
}

#[test]
fn test_vault_operations() {
    let path = "test_vault.vault";
    let pass = "VaultSecret1";
    if std::path::Path::new(path).exists() {
        fs::remove_file(path).unwrap();
    }

    // Create & Write
    {
        let mut v = Vault::open(path, pass).expect("Create failed");
        v.write_file("secret.txt", b"Top Secret Data").expect("Write failed");
    }

    // Read
    {
        let mut v = Vault::open(path, pass).expect("Open failed");
        let data = v.read_file("secret.txt").expect("Read failed");
        assert_eq!(data, b"Top Secret Data");
    }

    fs::remove_file(path).unwrap();
}
