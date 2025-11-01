use crate::*;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    Generate {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "24")]
        words: u32,
    },
    Show {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "0")]
        account: u32,
        #[arg(long, default_value = "false")]
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
        #[arg(long, default_value = "false")]
        reveal: bool,
    },
    Privatekey {
        #[arg(short, long)]
        password: String,
        #[arg(short, long)]
        chain: String,
        #[arg(short, long, default_value = "0")]
        account: u32,
        #[arg(long, default_value = "false")]
        qr: bool,
    },
    Convert {
        #[arg(short, long)]
        key: String,
        #[arg(long, default_value = "false")]
        testnet: bool,
        #[arg(short, long, default_value = "false")]
        uncompressed: bool,
    },
    Restore {
        #[arg(short, long)]
        mnemonic: String,
        #[arg(short, long)]
        password: String,
    },
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
        #[arg(long, default_value = "false")]
        confirm: bool,
    },
}

pub fn execute_command(command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Generate { password, words } => {
            crate::generate_wallet(&password, words)?;
        }
        Commands::Show { password, account, qr } => {
            crate::show_wallet(&password, account, qr)?;
        }
        Commands::Derive { password, count } => {
            crate::derive_multiple_accounts(&password, count)?;
        }
        Commands::Mnemonic { password, reveal } => {
            crate::export_mnemonic(&password, reveal)?;
        }
        Commands::Privatekey { password, chain, account, qr } => {
            crate::export_private_key(&password, &chain, account, qr)?;
        }
        Commands::Convert { key, testnet, uncompressed } => {
            convert::run_convert(&key, testnet, uncompressed)?;
        }
        Commands::Restore { mnemonic, password } => {
            crate::restore_wallet(&mnemonic, &password)?;
        }
        Commands::ChangePassword { old, new } => {
            crate::change_password(&old, &new)?;
        }
        Commands::Verify { password } => {
            crate::verify_wallet(&password)?;
        }
        Commands::Delete { confirm } => {
            crate::delete_wallet(confirm)?;
        }
    }
    Ok(())
}
