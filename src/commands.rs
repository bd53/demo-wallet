use crate::*;
use clap::Subcommand;

use crate::derive::*;
use crate::ops::*;
use crate::wallet::*;

#[derive(Subcommand)]
pub enum Commands {
    Generate {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "24")]
        words: u32,
    },
    #[command(name = "generate-seedless")]
    GenerateSeedless {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "3")]
        threshold: u8,
        #[arg(short = 'n', long, default_value = "5")]
        shares: u8,
    },
    Show {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "0")]
        account: u32,
        #[arg(long)]
        qr: bool,
    },
    Derive {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "5")]
        count: u32,
    },
    Mnemonic {
        #[arg(short, long)]
        password: String,
        #[arg(long)]
        reveal: bool,
    },
    #[command(name = "privatekey")]
    Privatekey {
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        chain: String,
        #[arg(short = 'i', long, default_value = "0")]
        account: u32,
        #[arg(long)]
        qr: bool,
    },
    #[command(name = "share")]
    Share {
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        number: u8,
        #[arg(long)]
        qr: bool,
        #[arg(short, long)]
        output: Option<String>,
    },
    Convert {
        #[arg(short, long)]
        key: String,
        #[arg(short, long)]
        testnet: bool,
        #[arg(short, long)]
        uncompressed: bool,
    },
    Restore {
        #[arg(short, long)]
        mnemonic: String,
        #[arg(short, long)]
        password: String,
    },
    #[command(name = "restore-seedless")]
    RestoreSeedless {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, num_args = 1..)]
        shares: Vec<String>,
    },
    #[command(name = "change-password")]
    ChangePassword {
        #[arg(short, long)]
        old: String,
        #[arg(short, long)]
        new: String,
    },
    Verify {
        #[arg(short, long)]
        password: String,
    },
    Delete {
        #[arg(long)]
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
