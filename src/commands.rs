use crate::*;
use clap::Subcommand;

#[derive(Subcommand)]
pub enum Commands {
    Generate {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "24")]
        words: u32,
        #[arg(long, default_value = "false")]
        online: bool,
    },
    Show {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "0")]
        account: u32,
        #[arg(long, default_value = "false")]
        qr: bool,
        #[arg(long, default_value = "false")]
        online: bool,
    },
    Derive {
        #[arg(short, long)]
        password: String,
        #[arg(short, long, default_value = "5")]
        count: u32,
        #[arg(long, default_value = "false")]
        online: bool,
    },
    Mnemonic {
        #[arg(short, long)]
        password: String,
        #[arg(long, default_value = "false")]
        reveal: bool,
        #[arg(long, default_value = "false")]
        online: bool,
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
        #[arg(long, default_value = "false")]
        online: bool,
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
        #[arg(long, default_value = "false")]
        online: bool,
    },
    ChangePassword {
        #[arg(short, long)]
        old: String,
        #[arg(short, long)]
        new: String,
        #[arg(long, default_value = "false")]
        online: bool,
    },
    Verify {
        #[arg(short, long)]
        password: String,
        #[arg(long, default_value = "false")]
        online: bool,
    },
    Delete {
        #[arg(long, default_value = "false")]
        confirm: bool,
        #[arg(long, default_value = "false")]
        online: bool,
    },
}

pub fn execute_command(command: Commands) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        Commands::Generate { password, words, online } => {
            if !status(online) { return Ok(()); }
            generate_wallet(&password, words)?;
        }
        Commands::Show { password, account, qr, online } => {
            if !status(online) { return Ok(()); }
            show_wallet(&password, account, qr)?;
        }
        Commands::Derive { password, count, online } => {
            if !status(online) { return Ok(()); }
            derive_multiple_accounts(&password, count)?;
        }
        Commands::Mnemonic { password, reveal, online } => {
            if !status(online) { return Ok(()); }
            export_mnemonic(&password, reveal)?;
        }
        Commands::Privatekey { password, chain, account, qr, online } => {
            if !status(online) { return Ok(()); }
            export_private_key(&password, &chain, account, qr)?;
        }
        Commands::Convert { key, testnet, uncompressed } => {
            convert::run_convert(&key, testnet, uncompressed)?;
        }
        Commands::Restore { mnemonic, password, online } => {
            if !status(online) { return Ok(()); }
            restore_wallet(&mnemonic, &password)?;
        }
        Commands::ChangePassword { old, new, online } => {
            if !status(online) { return Ok(()); }
            change_password(&old, &new)?;
        }
        Commands::Verify { password, online } => {
            if !status(online) { return Ok(()); }
            verify_wallet(&password)?;
        }
        Commands::Delete { confirm, online } => {
            if !status(online) { return Ok(()); }
            delete_wallet(confirm)?;
        }
    }
    Ok(())
}
