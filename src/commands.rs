use crate::*;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    /// Generate a new wallet with a mnemonic phrase
    Generate {
        #[arg(short, long, help = "Password to encrypt the wallet")]
        password: String,
        #[arg(short, long, default_value = "24", help = "Number of mnemonic words (12 or 24)")]
        words: u32,
    },
    /// Show wallet addresses for a specific account
    Show {
        #[arg(short, long, help = "Password to decrypt the wallet")]
        password: String,
        #[arg(short, long, default_value = "0", help = "Account index (0-19)")]
        account: u32,
        #[arg(long, help = "Display QR codes for addresses")]
        qr: bool,
    },
    /// Derive multiple accounts from the wallet
    Derive {
        #[arg(short, long, help = "Password to decrypt the wallet")]
        password: String,
        #[arg(short, long, default_value = "5", help = "Number of accounts to derive (1-20)")]
        count: u32,
    },
    /// Export the mnemonic phrase
    Mnemonic {
        #[arg(short, long, help = "Password to decrypt the wallet")]
        password: String,
        #[arg(long, help = "Actually display the mnemonic phrase")]
        reveal: bool,
    },
    /// Export a private key for a specific chain and account
    #[command(name = "privatekey")]
    Privatekey {
        #[arg(short, long, help = "Password to decrypt the wallet")]
        password: String,
        #[arg(short, long, help = "Chain name (bitcoin, ethereum, solana)")]
        chain: String,
        #[arg(short = 'i', long, default_value = "0", help = "Account index (0-19)")]
        account: u32,
        #[arg(long, help = "Display QR code for private key")]
        qr: bool,
    },
    /// Convert a private key between different formats
    Convert {
        #[arg(short, long, help = "Private key to convert")]
        key: String,
        #[arg(long, help = "Use testnet instead of mainnet")]
        testnet: bool,
        #[arg(short, long, help = "Use uncompressed format")]
        uncompressed: bool,
    },
    /// Restore a wallet from a mnemonic phrase
    Restore {
        #[arg(short, long, help = "Mnemonic phrase to restore")]
        mnemonic: String,
        #[arg(short, long, help = "Password to encrypt the wallet")]
        password: String,
    },
    /// Change the wallet password
    #[command(name = "change-password")]
    ChangePassword {
        #[arg(short, long, help = "Current password")]
        old: String,
        #[arg(short, long, help = "New password")]
        new: String,
    },
    /// Verify wallet integrity and display metadata
    Verify {
        #[arg(short, long, help = "Password to decrypt the wallet")]
        password: String,
    },
    /// Permanently delete the wallet
    Delete {
        #[arg(long, help = "Confirm deletion without prompting")]
        confirm: bool,
    },
}

pub fn execute_command(command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Generate { password, words } => generate_wallet(&password, words),
        Commands::Show { password, account, qr } => show_wallet(&password, account, qr),
        Commands::Derive { password, count } => derive_multiple_accounts(&password, count),
        Commands::Mnemonic { password, reveal } => export_mnemonic(&password, reveal),
        Commands::Privatekey { password, chain, account, qr } => export_private_key(&password, &chain, account, qr),
        Commands::Convert { key, testnet, uncompressed } => convert::run_convert(&key, testnet, uncompressed),
        Commands::Restore { mnemonic, password } => restore_wallet(&mnemonic, &password),
        Commands::ChangePassword { old, new } => change_password(&old, &new),
        Commands::Verify { password } => verify_wallet(&password),
        Commands::Delete { confirm } => delete_wallet(confirm),
    }
}
