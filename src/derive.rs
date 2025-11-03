use solana_sdk::signature::{Keypair as SolanaKeypair, SeedDerivable, Signer};
use std::fs;
use tiny_keccak::{Hasher, Keccak};
use zeroize::Zeroizing;

use crate::crypto::*;
use crate::constants::*;
use crate::ops::*;
use crate::types::*;
use crate::utils::*;

type DeriveResult = Result<(String, Zeroizing<Vec<u8>>), Box<dyn std::error::Error>>;

pub fn derive_bitcoin_addresses(seed: &[u8], index: u32) -> Result<BitcoinAddresses, Box<dyn std::error::Error>> {
    validate_account_index(index)?;
    use bitcoin::{Address, CompressedPublicKey, Network, NetworkKind, PrivateKey, PublicKey, bip32::{ChildNumber, DerivationPath, Xpriv}, secp256k1::Secp256k1};
    let secp = Secp256k1::new();
    let xprv = Xpriv::new_master(Network::Bitcoin, seed)?;
    let path = DerivationPath::from(vec![
        ChildNumber::from_hardened_idx(44)?,
        ChildNumber::from_hardened_idx(0)?,
        ChildNumber::from_hardened_idx(0)?,
        ChildNumber::from_normal_idx(0)?,
        ChildNumber::from_normal_idx(index)?,
    ]);
    let derived = xprv.derive_priv(&secp, &path)?;
    let network_kind: NetworkKind = Network::Bitcoin.into();
    let private_key = PrivateKey::new(derived.private_key, network_kind);
    let public_key = PublicKey::from_private_key(&secp, &private_key);
    let p2pkh = Address::p2pkh(public_key, Network::Bitcoin).to_string();
    let compressed_pk = CompressedPublicKey::from_private_key(&secp, &private_key).map_err(|e| format!("Failed to create compressed public key: {:?}", e))?;
    let p2wpkh = Address::p2wpkh(&compressed_pk, Network::Bitcoin).to_string();
    let p2sh = Address::p2shwpkh(&compressed_pk, network_kind).to_string();
    Ok(BitcoinAddresses { p2pkh, p2wpkh, p2sh })
}

pub fn derive_ethereum_address(seed: &[u8], index: u32) -> Result<String, Box<dyn std::error::Error>> {
    validate_account_index(index)?;
    use bip32::XPrv;
    use k256::ecdsa::SigningKey;
    let path = format!("m/44'/60'/0'/0/{}", index);
    let xprv = XPrv::derive_from_path(seed, &path.parse()?)?;
    let secret_bytes = xprv.to_bytes();
    let signing_key = SigningKey::from_bytes(&secret_bytes.into())?;
    let verifying_key = signing_key.verifying_key();
    let public_bytes = verifying_key.to_encoded_point(false);
    let mut hasher = Keccak::v256();
    hasher.update(&public_bytes.as_bytes()[1..]);
    let mut hash = [0u8; 32];
    hasher.finalize(&mut hash);
    let address = format!("0x{}", hex::encode(&hash[12..]));
    Ok(address)
}

pub fn derive_solana_address(seed: &[u8], index: u32) -> DeriveResult {
    validate_account_index(index)?;
    use bip32::XPrv;
    let path = format!("m/44'/501'/{}'", index);
    let xprv = XPrv::derive_from_path(seed, &path.parse()?)?;
    let secret_bytes = xprv.to_bytes();
    let mut seed_bytes = Zeroizing::new([0u8; 32]);
    seed_bytes.copy_from_slice(&secret_bytes);
    let keypair = SolanaKeypair::from_seed(&*seed_bytes)?;
    let address = keypair.pubkey().to_string();
    let secret_key = Zeroizing::new(keypair.to_bytes().to_vec());
    Ok((address, secret_key))
}

pub fn derive_all_addresses(secure_seed: &SecureSeed, index: u32) -> Result<Addresses, Box<dyn std::error::Error>> {
    let seed = secure_seed.as_bytes();
    let bitcoin = derive_bitcoin_addresses(seed, index)?;
    let ethereum = derive_ethereum_address(seed, index)?;
    let (solana, _secret) = derive_solana_address(seed, index)?;
    Ok(Addresses { bitcoin, ethereum, solana })
}

pub fn derive_multiple_accounts(password: &str, count: u32) -> Result<(), Box<dyn std::error::Error>> {
    check_wallet_exists()?;
    if !(1..=ACCOUNT_MAX).contains(&count) {
        return Err(format!("You can only derive between 1 and {} accounts.", ACCOUNT_MAX).into());
    }
    let metadata = load_metadata()?.ok_or("Metadata not found")?;
    let secure_seed = match metadata.wallet_type {
        WalletType::Mnemonic => {
            let wallet_file = get_wallet_file()?;
            let contents = fs::read_to_string(wallet_file)?;
            let wallet: EncryptedWallet = serde_json::from_str(&contents)?;
            let secure_mnemonic = decrypt_mnemonic(&wallet, password)?;
            secure_mnemonic.to_seed("")
        }
        WalletType::Seedless => {
            let config = metadata.shamir_config.ok_or("Shamir configuration not found")?;
            let secret = recover_secret_from_shares(password, config.threshold)?;
            SecureSeed::from_entropy(&secret)
        }
    };
    println!("\nDeriving {} account(s)...\n", count);
    for i in 0..count {
        let addresses = derive_all_addresses(&secure_seed, i)?;
        println!("--------------------------------------------------------------");
        println!("Account {}:", i);
        println!("  Bitcoin (SegWit): {}", addresses.bitcoin.p2wpkh);
        println!("  Ethereum: {}", addresses.ethereum);
        println!("  Solana: {}", addresses.solana);
    }
    println!("--------------------------------------------------------------\n");
    update_metadata(Some(count))?;
    Ok(())
}
