use clap::Parser;
use cws::commands::{self, Commands};

mod gui;

#[derive(Parser)]
#[command(name = env!("CARGO_PKG_NAME"), about = env!("CARGO_PKG_DESCRIPTION"), author = env!("CARGO_PKG_AUTHORS"), version = env!("CARGO_PKG_VERSION"))]
struct Cli {
    #[arg(long)]
    cli: bool,
    #[command(subcommand)]
    command: Option<Commands>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    if cli.cli || cli.command.is_some() {
        if let Some(command) = cli.command {
            if let Err(e) = commands::execute_command(command) {
                eprintln!("\nError: {}\n", e);
                std::process::exit(1);
            }
        } else {
            eprintln!("Error: --cli flag requires a subcommand");
            std::process::exit(1);
        }
    } else if let Err(e) = gui::run_gui() {
        eprintln!("GUI Error: {}", e);
        std::process::exit(1);
    }
    Ok(())
}
