//! # cws
//!
//! Example crypto wallet for offline key management and cold storage.
//!
//! This crate provides functionality for managing cryptocurrency wallets with a focus
//! on offline key management and cold storage security.
//!
//! ## Usage
//!
//! This is primarily a command-line application. For CLI usage, see the examples below.
//!
//! ### Commands
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
//! Or:
//!
//! ```bash
//! # Using cargo
//! just run <command> [options]
//!
//! # For optimized builds
//! just run-release <command> [options]
//!
//! # Using the compiled binary
//! just exec <command> [options]
//! ```
//!
//! ### Generate Wallet
//!
//! Generate with 24-word mnemonic:
//!
//! ```bash
//! cargo run -- generate -p "password"
//! ```
//!
//! Generate with 12-word mnemonic:
//!
//! ```bash
//! cargo run -- generate -p "password" -w 12
//! ```
//!
//! **Flags:**
//! - `-p, --password <password>` (Required): Password for encryption (min. 8 characters)
//! - `-w, --words <count>` (Optional): Mnemonic word count (12 or 24, default = `24`)
//!
//! **Note:** Generated addresses are fully functional and can receive and hold funds indefinitely.
//! If you want to access or transfer funds from an address, export the private key (or mnemonic phrase)
//! and import it into a trusted, compatible online wallet.
//!
//! ### Generate Seedless Wallet
//!
//! ```bash
//! cargo run -- generate-seedless -p "password"
//! ```
//!
//! ```bash
//! cargo run -- generate-seedless -p "password" -t 3 -n 5
//! ```
//!
//! **Flags:**
//! - `-p, --password <password>` (Required): Password for encryption (min. 8 characters)
//! - `-t, --threshold <count>` (Optional): Min. number of shares to recover wallet (range = 2–10, default = `3`)
//! - `-n, --shares <count>` (Optional): Number of shares to generate (range = 3–10, default = `5`)
//!
//! Seedless wallets use SSS _(Shamir Secret Sharing)_ to remove the need for mnemonic phrases.
//! Your wallet is split into multiple encrypted shares, each stored as an individual file inside
//! `.cws/.shares/`. To restore your wallet, you must provide at least the threshold
//! number of shares you originally configured.
//!
//! ### View Your Addresses
//!
//! Show default account (account 0):
//!
//! ```bash
//! cargo run -- show -p "password"
//! ```
//!
//! Show specific account (account 5):
//!
//! ```bash
//! cargo run -- show -p "password" -a 5
//! ```
//!
//! Show default account + QR codes:
//!
//! ```bash
//! cargo run -- show -p "password" --qr
//! ```
//!
//! Show specific account (account 3) + QR codes:
//!
//! ```bash
//! cargo run -- show -p "password" -a 3 --qr
//! ```
//!
//! **Flags:**
//! - `-p, --password <password>` (Required): Wallet decryption password
//! - `-a, --account <index>` (Optional): Account index (range = 0-max, default = `0`)
//! - `--qr` (Optional): Display QR codes for addresses
//!
//! ### Derive Multiple Accounts
//!
//! Generate multiple receiving addresses from the same seed:
//!
//! Derive first 5 accounts:
//!
//! ```bash
//! cargo run -- derive -p "password" -c 5
//! ```
//!
//! Derive up to 20 accounts:
//!
//! ```bash
//! cargo run -- derive -p "password" -c 20
//! ```
//!
//! **Flags:**
//! - `-p, --password <password>` (Required): Wallet decryption password
//! - `-c, --count <number>` (Optional): Accounts to derive (range = 1-max, default = `5`)
//!
//! ### Export Mnemonic
//!
//! ```bash
//! cargo run -- mnemonic -p "password" --reveal
//! ```
//!
//! **Flags:**
//! - `-p, --password <password>` (Required): Wallet decryption password
//! - `--reveal` (Optional): Display mnemonic
//!
//! ### Export Private Key
//!
//! Export private key for a specific chain:
//!
//! ```bash
//! cargo run -- privatekey -p "password" -c ethereum
//! ```
//!
//! Export private key for account 1 + QR code:
//!
//! ```bash
//! cargo run -- privatekey -p "password" -c solana -i 1 --qr
//! ```
//!
//! **Flags:**
//! - `-p, --password <password>` (Required): Wallet decryption password
//! - `-c, --chain <chain>` (Required): Blockchain: `bitcoin`, `ethereum`, or `solana`
//! - `-i, --account <index>` (Optional): Account index (range = 0-max, default = `0`)
//! - `--qr` (Optional): Display private key as QR code
//!
//! **Warning:** Some tools expect WIF format. Convert hex to WIF if needed.
//! This command technically defeats the purpose of cold storage. It's provided only for users
//! who insist on accessing or managing their funds from another device, which is **not**
//! recommended for secure cold storage setups.
//!
//! ### Export Share
//!
//! ```bash
//! cargo run -- share -p "password" -n 1
//! ```
//!
//! ```bash
//! cargo run -- share -p "password" -n 2 --qr
//! ```
//!
//! ```bash
//! cargo run -- share -p "password" -n 3 -o "./.backup/.shares"
//! ```
//!
//! **Flags:**
//! - `-p, --password <password>` (Required): Wallet decryption password
//! - `-n, --number <number>` (Required): Share number to export (1–N)
//! - `--qr` (Optional): Display share as QR code
//! - `-o, --output <path>` (Optional): Output file path for exported share
//!
//! Shares are stored in `.cws/.shares/` and named `share_#.bin`. To back up or
//! transfer a share securely, use this command to decrypt and export its contents. Never
//! reveal or share your decrypted share publicly, as combining enough shares can reconstruct
//! your wallet.
//!
//! ### Convert Private Key (hex to WIF)
//!
//! Convert a Bitcoin private key (mainnet):
//!
//! ```bash
//! cargo run -- convert -k <hex-private-key>
//! ```
//!
//! Convert a Bitcoin private key (testnet):
//!
//! ```bash
//! cargo run -- convert -k <hex-private-key> -t
//! ```
//!
//! Convert a Bitcoin private key (mainnet, uncompressed):
//!
//! ```bash
//! cargo run -- convert -k <hex-private-key> -u
//! ```
//!
//! Convert a Bitcoin private key (testnet, uncompressed):
//!
//! ```bash
//! cargo run -- convert -k <hex-private-key> -t -u
//! ```
//!
//! **Flags:**
//! - `-k, --key <hex>` (Required): Private key in 64-character hex format
//! - `-t, --testnet` (Optional): Convert key for Bitcoin testnet (default = mainnet)
//! - `-u, --uncompressed` (Optional): Use uncompressed format for public key (default = `compressed`)
//!
//! ### Restore Wallet
//!
//! If your local wallet file has been deleted or lost, you can use a mnemonic phrase to
//! recover your wallet:
//!
//! ```bash
//! cargo run -- restore -m "witch collapse practice feed shame open despair creek road again ice least" -p "new-password"
//! ```
//!
//! **Flags:**
//! - `-m, --mnemonic <phrase>` (Required): Full 12 or 24-word recovery phrase
//! - `-p, --password <password>` (Required): New encryption password (min. 8 characters)
//!
//! ### Restore Seedless Wallet
//!
//! ```bash
//! cargo run -- restore-seedless -p "password" -s "./.cws/.shares/share_1.bin" "./.cws/.shares/share_2.bin" "./.cws/.shares/share_3.bin"
//! ```
//!
//! **Flags:**
//! - `-p, --password <password>` (Required): Wallet decryption password
//! - `-s, --shares <paths>` (Required): One or more file paths to encrypted share files (space-separated)
//!
//! Example: If your wallet was generated with 5 total shares and a threshold of 3, you can
//! restore it with any 3 valid share files. All provided shares must use the same encryption
//! password used during wallet generation.
//!
//! ### Change Password
//!
//! ```bash
//! cargo run -- change-password -o "current-password" -n "new-password"
//! ```
//!
//! **Flags:**
//! - `-o, --old <password>` (Required): Current wallet password
//! - `-n, --new <password>` (Required): New password for encryption (min. 8 characters)
//!
//! ### Verify Wallet Integrity
//!
//! ```bash
//! cargo run -- verify -p "password"
//! ```
//!
//! **Flags:**
//! - `-p, --password <password>` (Required): Wallet decryption password
//!
//! ### Delete Wallet
//!
//! This permanently deletes your wallet file. Ensure you have your mnemonic backed up:
//!
//! ```bash
//! cargo run -- delete --confirm
//! ```
//!
//! **Flags:**
//! - `--confirm` (Required): Bypass prompt and confirm permanent wallet deletion
//!
//! ## HD Wallet Structure (BIP44)
//!
//! This wallet uses the BIP44 standard for hierarchical deterministic wallets:
//!
//! ```text
//! m / purpose' / coin_type' / account' / change / address_index
//!
//! Bitcoin: m/44'/0'/account'/0/0
//! Ethereum: m/44'/60'/account'/0/0
//! Solana: m/44'/501'/account'/0'
//! ```
//!
//! - Account 0: Your primary wallet
//! - Account 1+: Additional wallets from the same seed
//!
//! All accounts are cryptographically derived from your mnemonic.

pub mod commands;
pub mod constants;
pub mod convert;
pub mod crypto;
pub mod derive;
pub mod ops;
pub mod types;
pub mod utils;
pub mod wallet;
