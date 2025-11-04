use clap::Parser;
use cws::commands::{self, Commands};

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"), about = env!("CARGO_PKG_DESCRIPTION"), author = env!("CARGO_PKG_AUTHORS"), version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if let Err(e) = commands::execute_command(cli.command) {
        eprintln!("\nError: {}\n", e);
        std::process::exit(1);
    }
    Ok(())
}
