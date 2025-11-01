use bitcoin::{Network, NetworkKind, PrivateKey, PublicKey, Address};

pub fn run_convert(hex_key: &str, testnet: bool, uncompressed: bool) -> Result<(), Box<dyn std::error::Error>> {
    let key_bytes = hex::decode(hex_key.trim_start_matches("0x")).map_err(|_| "Invalid hex key format")?;
    if key_bytes.len() != 32 {
        return Err("Private key must be 32 bytes".into());
    }
    let network = if testnet { Network::Testnet } else { Network::Bitcoin };
    let network_kind: NetworkKind = network.into();
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&key_bytes)?;
    let private_key = PrivateKey { compressed: !uncompressed, network: network_kind, inner: sk };
    let pk = PublicKey::from_private_key(&secp, &private_key);
    let address = Address::p2pkh(pk, network);
    let wif = private_key.to_wif();
    println!("\nBitcoin Private Key Conversion");
    println!("--------------------------------");
    println!("Network: {}", if testnet { "Testnet" } else { "Mainnet" });
    println!("Format: {}", if uncompressed { "Uncompressed" } else { "Compressed" });
    println!("WIF: {}", wif);
    println!("Address: {}", address);
    println!("--------------------------------\n");
    Ok(())
}
