use aes_gcm::{Aes256Gcm, aead::{Aead, KeyInit}};
use bip39::{Language, Mnemonic};
use scrypt::{Params, password_hash::{SaltString, rand_core::{OsRng, RngCore}}};
use zeroize::Zeroizing;

use crate::constants::*;
use crate::types::*;

pub fn encrypt_data(data: &[u8], password: &str) -> Result<EncryptedData, Box<dyn std::error::Error>> {
    let salt = SaltString::generate(&mut OsRng);
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)?;
    let mut key = Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password.as_bytes(), salt.as_str().as_bytes(), &params, &mut key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let mut iv = [0u8; 12];
    OsRng.fill_bytes(&mut iv);
    let nonce = &iv.into();
    let ciphertext = cipher.encrypt(nonce, data).map_err(|e| format!("Encryption failed: {:?}", e))?;
    if ciphertext.len() < CIPHERTEXT_MIN {
        return Err("Encryption produced invalid ciphertext".into());
    }
    let tag_start = ciphertext.len() - 16;
    let content = hex::encode(&ciphertext[..tag_start]);
    let tag = hex::encode(&ciphertext[tag_start..]);
    Ok(EncryptedData { iv: hex::encode(iv), content, tag, salt: salt.as_str().to_string() })
}

pub fn decrypt_data(encrypted: &EncryptedData, password: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let params = Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, 32)?;
    let mut key = Zeroizing::new(vec![0u8; 32]);
    scrypt::scrypt(password.as_bytes(), encrypted.salt.as_bytes(), &params, &mut key)?;
    let cipher = Aes256Gcm::new_from_slice(&key)?;
    let iv = hex::decode(&encrypted.iv)?;
    let iv_array: [u8; 12] = iv.as_slice().try_into().map_err(|_| "Invalid IV length")?;
    let nonce = &iv_array.into();
    let content = hex::decode(&encrypted.content)?;
    let tag = hex::decode(&encrypted.tag)?;
    if tag.len() != 16 {
        return Err("Invalid authentication tag length".into());
    }
    let mut ciphertext = content;
    ciphertext.extend_from_slice(&tag);
    if ciphertext.len() < CIPHERTEXT_MIN {
        return Err("Invalid ciphertext length".into());
    }
    let plaintext = Zeroizing::new(cipher.decrypt(nonce, ciphertext.as_ref()).map_err(|_| "Decryption failed. Invalid password.")?);
    Ok(plaintext)
}

pub fn encrypt_mnemonic(mnemonic: &str, password: &str) -> Result<EncryptedWallet, Box<dyn std::error::Error>> {
    let encrypted = encrypt_data(mnemonic.as_bytes(), password)?;
    Ok(EncryptedWallet { iv: encrypted.iv, content: encrypted.content, tag: encrypted.tag, salt: encrypted.salt })
}

pub fn decrypt_mnemonic(wallet: &EncryptedWallet, password: &str) -> Result<SecureMnemonic, Box<dyn std::error::Error>> {
    let encrypted = EncryptedData { iv: wallet.iv.clone(), content: wallet.content.clone(), tag: wallet.tag.clone(), salt: wallet.salt.clone() };
    let plaintext = decrypt_data(&encrypted, password)?;
    let mnemonic_str = std::str::from_utf8(&plaintext)?;
    let _ = Mnemonic::from_phrase(mnemonic_str, Language::English).map_err(|_| "Invalid mnemonic in wallet file")?;
    let secure = SecureMnemonic::from_phrase(mnemonic_str.to_string());
    Ok(secure)
}

pub fn encrypt_share(share_data: &[u8], password: &str, share_number: u8) -> Result<EncryptedShare, Box<dyn std::error::Error>> {
    let encrypted = encrypt_data(share_data, password)?;
    Ok(EncryptedShare { number: share_number, iv: encrypted.iv, content: encrypted.content, tag: encrypted.tag, salt: encrypted.salt })
}

pub fn decrypt_share(share: &EncryptedShare, password: &str) -> Result<Zeroizing<Vec<u8>>, Box<dyn std::error::Error>> {
    let encrypted = EncryptedData { iv: share.iv.clone(), content: share.content.clone(), tag: share.tag.clone(), salt: share.salt.clone() };
    decrypt_data(&encrypted, password)
}
