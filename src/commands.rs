use crate::*;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new wallet with a mnemonic phrase
    Generate {
        #[arg(short, long, help = "Password for encryption (min. 8 characters).")]
        password: String,
        #[arg(short, long, default_value = "24", help = "Mnemonic word count (12/24, default = 24).")]
        words: u32,
    },
    /// Generate a seedless wallet
    #[command(name = "generate-seedless")]
    GenerateSeedless {
        #[arg(short, long, help = "Password used to encrypt each Shamir share (min. 8 characters).")]
        password: String,
        #[arg(short, long, default_value = "3", help = "Minimum number of shares required to recover the wallet (default = 3, range = 2–10).")]
        threshold: u8,
        #[arg(short = 'n', long, default_value = "5", help = "Total number of encrypted shares to generate (default = 5, range = 3–10).")]
        shares: u8,
    },
    /// Show wallet addresses for a specific account
    Show {
        #[arg(short, long, help = "Wallet decryption password.")]
        password: String,
        #[arg(short, long, default_value = "0", help = "Account index (0–19, default = 0).")]
        account: u32,
        #[arg(long, help = "Display QR codes for addresses.")]
        qr: bool,
    },
    /// Derive multiple accounts from the wallet
    Derive {
        #[arg(short, long, help = "Wallet decryption password.")]
        password: String,
        #[arg(short, long, default_value = "5", help = "Number of accounts to derive (1–20, default = 5).")]
        count: u32,
    },
    /// Export the mnemonic phrase (only for mnemonic-based wallets)
    Mnemonic {
        #[arg(short, long, help = "Wallet decryption password.")]
        password: String,
        #[arg(long, help = "Actually display the mnemonic phrase.")]
        reveal: bool,
    },
    /// Export a private key for a specific chain and account
    #[command(name = "privatekey")]
    Privatekey {
        #[arg(short, long, help = "Wallet decryption password.")]
        password: String,
        #[arg(short, long, help = "Blockchain to export key for: bitcoin, ethereum, or solana.")]
        chain: String,
        #[arg(short = 'i', long, default_value = "0", help = "Account index (0–19, default = 0).")]
        account: u32,
        #[arg(long, help = "Display private key as QR code.")]
        qr: bool,
    },
    /// Export a seedless wallet share
    #[command(name = "share")]
    Share {
        #[arg(short, long, help = "Wallet decryption password.")]
        password: String,
        #[arg(short, long, help = "Share number to export (1–N).")]
        number: u8,
        #[arg(long, help = "Display share as QR code.")]
        qr: bool,
        #[arg(short, long, help = "Output file path for exported share.")]
        output: Option<String>,
    },
    /// Convert a private key between different formats
    Convert {
        #[arg(short, long, help = "Private key in 64-character hex format.")]
        key: String,
        #[arg(short, long, help = "Convert key for Bitcoin testnet (default = mainnet).")]
        testnet: bool,
        #[arg(short, long, help = "Use uncompressed format for public key (default = compressed).")]
        uncompressed: bool,
    },
    /// Restore a wallet from a mnemonic phrase
    Restore {
        #[arg(short, long, help = "Full 12 or 24-word recovery phrase.")]
        mnemonic: String,
        #[arg(short, long, help = "New encryption password (min. 8 characters).")]
        password: String,
    },
    /// Restore a seedless wallet from multiple shares
    #[command(name = "restore-seedless")]
    RestoreSeedless {
        #[arg(short, long, help = "Wallet decryption password.")]
        password: String,
        #[arg(short, long, num_args = 1.., help = "One or more file paths to encrypted share files (space-separated).")]
        shares: Vec<String>,
    },
    /// Change the wallet password
    #[command(name = "change-password")]
    ChangePassword {
        #[arg(short, long, help = "Current wallet password.")]
        old: String,
        #[arg(short, long, help = "New password for encryption (min. 8 characters).")]
        new: String,
    },
    /// Verify wallet integrity and display metadata
    Verify {
        #[arg(short, long, help = "Wallet decryption password.")]
        password: String,
    },
    /// Permanently delete the wallet
    Delete {
        #[arg(long, help = "Bypass prompt and confirm permanent wallet deletion.")]
        confirm: bool,
    },
}

pub fn execute_command(command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Generate { password, words } => generate_wallet(&password, words),
        Commands::GenerateSeedless { password, threshold, shares } => generate_wallet_seedless(&password, threshold, shares),
        Commands::Show { password, account, qr } => show_wallet(&password, account, qr),
        Commands::Derive { password, count } => derive_multiple_accounts(&password, count),
        Commands::Mnemonic { password, reveal } => export_mnemonic(&password, reveal),
        Commands::Privatekey { password, chain, account, qr } => export_private_key(&password, &chain, account, qr),
        Commands::Share { password, number, qr, output } => export_share(&password, number, qr, output.as_deref()),
        Commands::Convert { key, testnet, uncompressed } => convert::run_convert(&key, testnet, uncompressed),
        Commands::Restore { mnemonic, password } => restore_wallet(&mnemonic, &password),
        Commands::RestoreSeedless { password, shares } => { restore_wallet_seedless(&password, &shares) }
        Commands::ChangePassword { old, new } => change_password(&old, &new),
        Commands::Verify { password } => verify_wallet(&password),
        Commands::Delete { confirm } => delete_wallet(confirm),
    }
}
