//! # Usage
//!
//! This is primarily a command-line application. For CLI usage, see the examples below.
//!
//! You can run the project using Cargo or the compiled binary:
//!
//! ```bash
//! # Using cargo
//! cargo run -- <command> [options]
//!
//! # For optimized builds
//! cargo run --release -- <command> [options]
//!
//! # Using the compiled binary
//! ./target/release/cws <command> [options]
//! ```
//!
//! ## Quick Start
//!
//! 1. Generate wallet:
//!    ```bash
//!    cargo run --release -- generate -p "password"
//!    ```
//!
//! 2. View addresses:
//!    ```bash
//!    cargo run --release -- show -p "password"
//!    ```
//!
//! 3. Back up mnemonic (keep this safe and offline):
//!    ```bash
//!    cargo run --release -- mnemonic -p "password" --reveal
//!    ```
//!
//! ## Commands
//!
//! ### Generate Wallet
//!
//! Create a mnemonic-based HD wallet with BIP39 recovery phrase.
//!
//! 1. Generate with 24-word mnemonic (recommended):
//!    ```bash
//!    cargo run --release -- generate -p "password"
//!    ```
//!
//! 2. Generate with 12-word mnemonic:
//!    ```bash
//!    cargo run --release -- generate -p "password" -w 12
//!    ```
//!
//! **Flags:**
//! - `-p, --password <PASSWORD>` (Required): Encryption password (min. 8 characters, must include uppercase, lowercase, number, and symbol)
//! - `-w, --words <COUNT>` (Optional): Mnemonic word count (12 or 24, default = `24`)
//!
//! **Output:**
//! - Creates `~/.cws/wallet.json` (encrypted mnemonic)
//! - Creates `~/.cws/metadata.json` (wallet configuration)
//! - Displays initial addresses for Bitcoin, Ethereum, and Solana (account 0)
//!
//! **Generated addresses can receive funds immediately and will remain valid indefinitely.**
//!
//! **Note:** Write down your mnemonic phrase and store it securely offline. Use `mnemonic --reveal` to view it later.
//!
//! ### Generate Seedless Wallet
//!
//! Create a wallet using Shamir Secret Sharing instead of a mnemonic phrase.
//!
//! 1. Default: 3-of-5 configuration (need any 3 shares to recover):
//!    ```bash
//!    cargo run --release -- generate-seedless -p "password"
//!    ```
//!
//! 2. Custom: 2-of-3 configuration:
//!    ```bash
//!    cargo run --release -- generate-seedless -p "password" -t 2 -n 3
//!    ```
//!
//! 3. High security: 5-of-7 configuration:
//!    ```bash
//!    cargo run --release -- generate-seedless -p "password" -t 5 -n 7
//!    ```
//!
//! **Flags:**
//! - `-p, --password <PASSWORD>` (Required): Encryption password for all shares
//! - `-t, --threshold <COUNT>` (Optional): Minimum shares needed for recovery (range = 2-10, default = `3`)
//! - `-n, --shares <COUNT>` (Optional): Total shares to generate (range = 3-10, default = `5`)
//!
//! **Output:**
//! - Creates `~/.cws/wallet.json` (seedless marker)
//! - Creates `~/.cws/metadata.json` (wallet configuration with Shamir parameters)
//! - Creates `~/.cws/.shares/share_N.json` (one file per share)
//! - Displays initial addresses for Bitcoin, Ethereum, and Solana (account 0)
//!
//! **Export each share using `share` command and store in separate secure locations.**
//!
//! **Note:** You need ANY threshold number of shares to recover your wallet.
//! Individual shares are useless alone - no single point of failure.
//!
//! ### Show Addresses
//!
//! Display wallet addresses.
//!
//! 1. Show default account (account 0):
//!    ```bash
//!    cargo run --release -- show -p "password"
//!    ```
//!
//! 2. Show specific account:
//!    ```bash
//!    cargo run --release -- show -p "password" -a 5
//!    ```
//!
//! 3. Show with QR codes for easy scanning:
//!    ```bash
//!    cargo run --release -- show -p "password" --qr
//!    ```
//!
//! 4. Show specific account with QR codes:
//!    ```bash
//!    cargo run --release -- show -p "password" -a 3 --qr
//!    ```
//!
//! **Flags:**
//! - `-p, --password <PASSWORD>` (Required): Wallet decryption password
//! - `-a, --account <INDEX>` (Optional): Account index (range = 0-max, default = `0`)
//! - `--qr` (Optional): Display QR codes for all addresses
//!
//! **Output:**
//! - Bitcoin Legacy (P2PKH) address
//! - Bitcoin Native SegWit (P2WPKH) address
//! - Bitcoin Wrapped SegWit (P2SH-P2WPKH) address
//! - Ethereum address (EIP-55 checksummed)
//! - Solana address (base58-encoded)
//!
//! ### Derive Multiple Accounts
//!
//! Generate multiple accounts derived from the same wallet seed.
//!
//! 1. Derive first 5 accounts:
//!    ```bash
//!    cargo run --release -- derive -p "password" -c 5
//!    ```
//!
//! 2. Derive up to maximum (20 accounts):
//!    ```bash
//!    cargo run --release -- derive -p "password" -c 20
//!    ```
//!
//! **Flags:**
//! - `-p, --password <PASSWORD>` (Required): Wallet decryption password
//! - `-c, --count <NUMBER>` (Optional): Number of accounts to derive (range = 1-max, default = `5`)
//!
//! **Output:**
//! - Displays a table with account numbers and their Native SegWit Bitcoin, Ethereum, and Solana addresses
//! - Updates metadata with the highest account index derived
//!
//! **Use Cases:**
//! - Account 0: Personal savings
//! - Account 1: Business transactions
//! - Account 2: Trading funds
//! - Account 3: Long-term investment
//!
//! ### Export Mnemonic
//!
//! View wallet BIP39 recovery phrase.
//!
//! 1. Verify password without showing mnemonic:
//!    ```bash
//!    cargo run --release -- mnemonic -p "password"
//!    ```
//!
//! 2. Display the mnemonic phrase (sensitive!):
//!    ```bash
//!    cargo run --release -- mnemonic -p "password" --reveal
//!    ```
//!
//! **Flags:**
//! - `-p, --password <PASSWORD>` (Required): Wallet decryption password
//! - `--reveal` (Optional): Actually display the mnemonic phrase
//!
//! **This command will fail for seedless wallets. Use `share` command instead.**
//!
//! **Note:** This displays your complete recovery phrase. Anyone with your mnemonic
//! can fully reconstruct and control your wallet. Only use in a secure, private
//! environment. Never share your mnemonic, take screenshots, or store it digitally.
//!
//! ### Export Private Key
//!
//! Export private key for a specific blockchain and account.
//!
//! 1. Export Bitcoin private key (hex format):
//!    ```bash
//!    cargo run --release -- privatekey -p "password" -c bitcoin
//!    ```
//!
//! 2. Export Ethereum private key for account 1:
//!    ```bash
//!    cargo run --release -- privatekey -p "password" -c ethereum -i 1
//!    ```
//!
//! 3. Export Solana private key with QR code:
//!    ```bash
//!    cargo run --release -- privatekey -p "password" -c solana --qr
//!    ```
//!
//! 4. Export for specific account with QR code:
//!    ```bash
//!    cargo run --release -- privatekey -p "password" -c ethereum -i 5 --qr
//!    ```
//!
//! **Flags:**
//! - `-p, --password <PASSWORD>` (Required): Wallet decryption password
//! - `-c, --chain <CHAIN>` (Required): Target blockchain (`bitcoin`, `ethereum`, or `solana`)
//! - `-i, --account <INDEX>` (Optional): Account index (range = 0-max, default = `0`)
//! - `--qr` (Optional): Display private key as QR code
//!
//! **Output:**
//! - Bitcoin: 64-character hexadecimal (use `convert` command for WIF format)
//! - Ethereum: Hexadecimal with `0x` prefix
//! - Solana: Base58-encoded secret key
//!
//! **Never share private keys or display them on untrusted devices.**
//!
//! **Note:** This command should only be used when absolutely
//! necessary to import keys into another trusted wallet.
//!
//! ### Export Share
//!
//! Export an encrypted share from a seedless wallet.
//!
//! 1. Display share 1:
//!    ```bash
//!    cargo run --release -- share -p "password" -n 1
//!    ```
//!
//! 2. Display share 2 as QR code:
//!    ```bash
//!    cargo run --release -- share -p "password" -n 2 --qr
//!    ```
//!
//! 3. Export share 3 to a file:
//!    ```bash
//!    cargo run --release -- share -p "password" -n 3 -o "./backup/share_3.json"
//!    ```
//!
//! 4. Export to USB drive:
//!    ```bash
//!    cargo run --release -- share -p "password" -n 4 -o "/media/usb/share_4.json"
//!    ```
//!
//! **Flags:**
//! - `-p, --password <PASSWORD>` (Required): Wallet decryption password
//! - `-n, --number <NUMBER>` (Required): Share number to export (1 to total shares)
//! - `--qr` (Optional): Display share as QR code
//! - `-o, --output <PATH>` (Optional): Save share to file at specified path
//!
//! **This command will fail for mnemonic-based wallets. Use `mnemonic` command instead.**
//!
//! **Note:** Store each share in a physically separate, secure location. Never keep
//! all shares together or in the same location. Anyone with threshold number of shares
//! can reconstruct your entire wallet. Individual shares reveal no information about the wallet.
//!
//! ### Convert Private Key
//!
//! Convert a Bitcoin private key to WIF (Wallet Import Format).
//!
//! 1. Convert for mainnet (compressed):
//!    ```bash
//!    cargo run --release -- convert -k privatekey
//!    ```
//!
//! 2. Convert for testnet:
//!    ```bash
//!    cargo run --release -- convert -k privatekey -t
//!    ```
//!
//! 3. Convert uncompressed (mainnet):
//!    ```bash
//!    cargo run --release -- convert -k privatekey -u
//!    ```
//!
//! 4. Convert uncompressed (testnet):
//!    ```bash
//!    cargo run --release -- convert -k privatekey -t -u
//!    ```
//!
//! 5. Accepts `0x` prefix:
//!    ```bash
//!    cargo run --release -- convert -k 0xprivatekey
//!    ```
//!
//! **Flags:**
//! - `-k, --key <HEX>` (Required): Private key as 64-character hexadecimal (with or without `0x` prefix)
//! - `-t, --testnet` (Optional): Convert for Bitcoin testnet (default = `mainnet`)
//! - `-u, --uncompressed` (Optional): Use uncompressed public key format (default = `compressed`)
//!
//! **Output:**
//! - Network type (Mainnet or Testnet)
//! - Key format (Compressed or Uncompressed)
//! - WIF-encoded private key
//! - Corresponding P2PKH Bitcoin address
//!
//! **Most modern wallets expect compressed format.**
//!
//! **Note:** Use uncompressed only for compatibility with
//! legacy systems. The same private key produces different
//! WIF strings and addresses depending on the compression setting.
//!
//! ### Restore Wallet
//!
//! Restore a mnemonic-based wallet from a BIP39 recovery phrase.
//!
//! 1. Restore from 12-word mnemonic:
//!    ```bash
//!    cargo run --release -- restore -m "twelve word mnemonic phrase..." -p "new-password"
//!    ```
//!
//! 2. Restore from 24-word mnemonic:
//!    ```bash
//!    cargo run --release -- restore -m "twenty four word mnemonic phrase..." -p "new-password"
//!    ```
//!
//! **Flags:**
//! - `-m, --mnemonic <phrase>` (Required): Complete 12 or 24-word BIP39 recovery phrase
//! - `-p, --password <PASSWORD>` (Required): New encryption password (min. 8 characters with complexity requirements)
//!
//! **Output:**
//! - Creates new `~/.cws/wallet.json` (encrypted mnemonic)
//! - Creates new `~/.cws/metadata.json` (wallet configuration)
//! - Displays restored addresses for account 0
//!
//! **Requirements:**
//! - No existing wallet (use `delete` first if needed)
//! - Valid BIP39 mnemonic phrase (correct word count and checksum)
//! - Password meeting security requirements
//!
//! **Use Cases:**
//! - Recover wallet after deleting local files
//! - Move wallet to a new device
//! - Import wallet from another BIP39-compatible application
//!
//! ### Restore Seedless Wallet
//!
//! Restore a seedless wallet by combining encrypted share files.
//!
//! 1. Restore with exactly threshold shares (3-of-5 example):
//!    ```bash
//!    cargo run --release -- restore-seedless -p "password" -s ~/.cws/.shares/share_1.json ~/.cws/.shares/share_2.json ~/.cws/.shares/share_3.json
//!    ```
//!
//! 2. Restore from backup locations:
//!    ```bash
//!    cargo run --release -- restore-seedless -p "password" -s /media/usb/share_1.json ~/Documents/share_3.json ~/Dropbox/share_5.json
//!    ```
//!
//! 3. Restore with more than threshold (any combination works):
//!    ```bash
//!    cargo run --release -- restore-seedless -p "password" -s share_1.json share_2.json share_3.json share_4.json
//!    ```
//!
//! **Flags:**
//! - `-p, --password <PASSWORD>` (Required): Password used to encrypt the shares (must be same as original)
//! - `-s, --shares <paths>` (Required): Space-separated paths to encrypted share files
//!
//! **Output:**
//! - Creates new `~/.cws/wallet.json` (seedless marker)
//! - Creates new `~/.cws/metadata.json` (wallet configuration)
//! - Regenerates all share files in `~/.cws/.shares/`
//! - Displays restored addresses for account 0
//! - Shows configuration (threshold-of-total) and number of shares used
//!
//! **Requirements:**
//! - No existing wallet (use `delete` first if needed)
//! - At least threshold number of valid share files
//! - All shares must use the same password
//! - Shares must be from the same wallet (compatible with each other)
//!
//! **Note:** If your wallet was generated with 5 total shares and a threshold of 3,
//! you can restore it using ANY 3 (or more) of those 5 shares. The shares can be
//! in any order and you don't need to know which specific shares you're using.
//!
//! ### Change Password
//!
//! Change wallet encryption password.
//!
//! ```bash
//! cargo run --release -- change-password -o "current-password" -n "new-secure-password"
//! ```
//!
//! **Flags:**
//! - `-o, --old <PASSWORD>` (Required): Current wallet password
//! - `-n, --new <PASSWORD>` (Required): New password (min. 8 characters with complexity requirements)
//!
//! **Behavior:**
//! - Mnemonic wallets: Re-encrypts `wallet.json` with new password
//! - Seedless wallets: Re-encrypts all share files with new password
//!
//! **Requirements:**
//! - Old password must be correct
//! - New password must meet security requirements (length, uppercase, lowercase, number, symbol)
//! - Wallet must exist
//!
//! **Note:** This does not change the underlying wallet or addresses,
//! only the encryption password. All derived addresses remain the same.
//!
//! ### Verify Wallet
//!
//! Verify wallet integrity and information.
//!
//! ```bash
//! cargo run --release -- verify -p "password"
//! ```
//!
//! **Flags:**
//! - `-p, --password <PASSWORD>` (Required): Wallet decryption password
//!
//! **Use Cases:**
//! - Test password before performing operations
//! - Check wallet integrity after system changes
//! - Verify which shares are available (seedless wallets)
//! - Review wallet configuration
//!
//! ### Delete Wallet
//!
//! Permanently delete wallet and all associated files.
//!
//! **Before Deleting:**
//! - Mnemonic wallets: Ensure you have your mnemonic phrase backed up securely
//! - Seedless wallets: Ensure you have exported all shares and stored them separately
//!
//! 1. Show warning and instructions (no deletion):
//!    ```bash
//!    cargo run --release -- delete
//!    ```
//!
//! 2. Permanently delete wallet (confirmed):
//!    ```bash
//!    cargo run --release -- delete --confirm
//!    ```
//!
//! **Flags:**
//! - `--confirm` (Required for deletion): Bypass confirmation prompt and proceed with deletion
//!
//! **Deleted Files:**
//! - `~/.cws/wallet.json` (wallet data)
//! - `~/.cws/metadata.json` (wallet configuration)
//! - `~/.cws/.shares/*.json` (all share files for seedless wallets)
//!
//! **This is irreversible.**
//!
//! # Architecture
//!
//! ## HD Wallet Structure (BIP44)
//!
//! All wallets follow the BIP44 hierarchical deterministic wallet standard:
//!
//! ```text
//! m / purpose' / coin_type' / account' / change / address_index
//!
//! Bitcoin:  m/44'/0'/account'/0/0
//! Ethereum: m/44'/60'/account'/0/0
//! Solana:   m/44'/501'/account'/0'
//! ```
//!
//! - Account 0: Your primary wallet (default)
//! - Account 1+: Additional wallets from the same seed
//!
//! All accounts are cryptographically derived from your mnemonic or recovered secret.
//!
//! ## Mnemonic Phrases (BIP39)
//!
//! Mnemonic-based wallets use BIP39 to generate a human-readable recovery
//! phrase from cryptographically secure random entropy. This phrase serves as a
//! complete backup of your entire wallet and can restore all derived accounts.
//!
//! - 12 words: 128 bits of entropy
//! - 24 words: 256 bits of entropy (recommended)
//!
//! ## Shamir Secret Sharing
//!
//! Seedless wallets eliminate mnemonic phrases by using Shamir Secret Sharing to
//! split the wallet master secret into multiple encrypted shares. You configure
//! a threshold (minimum shares needed) and total shares during generation.
//!
//! **Example: 3-of-5 configuration**
//! - Creates 5 shares
//! - Any 3 shares can recover the wallet
//! - Fewer than 3 shares reveal no information
//! - Individual shares can be stored in different secure locations
//!
//! **Benefits:**
//! - No mnemonic phrase to memorize, write down, or lose
//! - Shares can be distributed across multiple secure locations
//! - Losing some shares doesn't compromise security (if threshold is maintained)
//! - Each share is individually encrypted with your password
//! - No single point of failure
//!
//! **Back up shares using the `share` command and store them separately.**
//!
//! **Note:** If you lose too many shares
//! (below threshold), your wallet cannot be recovered.
//!
//! # Common Issues
//!
//! ### "No wallet found"
//! - Run `generate` or `generate-seedless` to create a wallet first
//!
//! ### "Wallet already exists"
//! - Use `delete --confirm` to remove existing wallet before creating new one
//! - Or use `verify` to check if you have a wallet
//!
//! ### "Decryption failed. Invalid password."
//! - Check password spelling and case sensitivity
//! - Verify caps lock is off
//! - Ensure you're using the correct wallet password
//!
//! ### "Not enough shares found"
//! - You need at least threshold number of shares
//! - Check that share files exist in `~/.cws/.shares/`
//! - Verify you're using the correct password for the shares
//!
//! ### "Invalid mnemonic phrase"
//! - Check word count (must be 12 or 24 words)
//! - Verify spelling of each word (use BIP39 word list)
//! - Ensure words are separated by spaces
//! - Check for typos or incorrect word order
//!
//! # Additional Resources
//!
//! - [https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)
//! - [https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)
//! - [https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki](https://github.com/bitcoin/bips/blob/master/bip-0044.mediawiki)
//! - [https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing](https://en.wikipedia.org/wiki/Shamir%27s_Secret_Sharing)
//!

/// CLI commands and execution logic.
pub mod commands;

/// Constants and configuration values.
pub mod constants;

/// Private key conversion utility (hex -> WIF).
pub mod convert;

/// Cryptographic operations.
pub mod crypto;

/// HD wallet derivation.
pub mod derive;

/// Core operations.
pub mod ops;

/// Type definitions and data structures.
pub mod types;

/// Utility functions and helpers.
pub mod utils;

/// Wallet generation.
pub mod wallet;
