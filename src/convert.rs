use bitcoin::{Address, Network, NetworkKind, PrivateKey, PublicKey};

pub fn run_convert(hex_key: &str, testnet: bool, uncompressed: bool) -> Result<String, Box<dyn std::error::Error>> {
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
    let output = format!(
        "Network: {}\n\
         Format: {}\n\
         WIF: {}\n\
         Address: {}",
        if testnet { "Testnet" } else { "Mainnet" },
        if uncompressed { "Uncompressed" } else { "Compressed" },
        wif,
        address
    );
    Ok(output)
}
