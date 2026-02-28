use clap::{Parser, Subcommand};
use std::error::Error;

#[derive(Parser)]
#[command(name = "netgap")]
#[command(about = "Network security scanner for discovering and assessing vulnerabilities on your LAN", long_about = None)]
#[command(version = "0.1.0")]
#[command(author = "GitHub Copilot")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// List available network interfaces
    Interfaces,
    /// Run a security scan on the selected network
    Scan {
        /// Network interface to scan (e.g., eth0)
        #[arg(short, long)]
        interface: Option<String>,

        /// Target network in CIDR notation (default: auto-detect)
        #[arg(short, long)]
        target: Option<String>,

        /// Quick scan mode (ARP + top 20 ports only)
        #[arg(long)]
        quick: bool,

        /// Deep scan mode (all checks enabled)
        #[arg(long)]
        deep: bool,
    },
    /// Display results from the last scan
    Report {
        /// Output format: table, json
        #[arg(short, long, default_value = "table")]
        format: String,
    },
    /// Continuous monitoring mode
    Watch,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Interfaces => {
            println!("📡 Available network interfaces:");
            println!("(Implementation in netgap-interfaces crate)");
        }
        Commands::Scan {
            interface,
            target,
            quick,
            deep,
        } => {
            let mode = if quick {
                "quick"
            } else if deep {
                "deep"
            } else {
                "standard"
            };
            println!("🔍 Starting {} scan...", mode);
            if let Some(iface) = interface {
                println!("  Interface: {}", iface);
            }
            if let Some(tgt) = target {
                println!("  Target: {}", tgt);
            }
            println!("(Full implementation coming in M2-M4)");
        }
        Commands::Report { format } => {
            println!("📊 Generating report in {} format", format);
            println!("(Implementation in netgap-report crate)");
        }
        Commands::Watch => {
            println!("👁️  Continuous monitoring mode");
            println!("(Implementation coming later)");
        }
    }

    Ok(())
}
