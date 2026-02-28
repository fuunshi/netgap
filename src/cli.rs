use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use colored::Colorize;

use crate::app;
use crate::model::{OutputFormat, ScanMode};

#[derive(Debug, Parser)]
#[command(
    name = "netgap",
    about = "Scan a local network for exposed services and common security gaps"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// List network interfaces that can be scanned.
    Interfaces,
    /// Run a scan against the selected interface.
    Scan {
        #[arg(short, long)]
        interface: Option<String>,
        #[arg(short, long, value_enum, default_value_t = ModeArg::Quick)]
        mode: ModeArg,
        #[arg(short, long, value_enum, default_value_t = OutputArg::Terminal)]
        output: OutputArg,
        #[arg(long)]
        output_file: Option<std::path::PathBuf>,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum ModeArg {
    Quick,
    Full,
}

impl From<ModeArg> for ScanMode {
    fn from(value: ModeArg) -> Self {
        match value {
            ModeArg::Quick => ScanMode::Quick,
            ModeArg::Full => ScanMode::Full,
        }
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum OutputArg {
    Terminal,
    Json,
    Html,
}

pub async fn run() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Command::Interfaces => {
            app::print_interfaces()?;
        }
        Command::Scan {
            interface,
            mode,
            output,
            output_file,
        } => {
            app::run_scan(
                interface.as_deref(),
                mode.into(),
                output.into(),
                output_file.as_deref(),
            )
            .await?;
        }
    }

    Ok(())
}

impl From<OutputArg> for OutputFormat {
    fn from(value: OutputArg) -> Self {
        match value {
            OutputArg::Terminal => OutputFormat::Terminal,
            OutputArg::Json => OutputFormat::Json,
            OutputArg::Html => OutputFormat::Html,
        }
    }
}

pub fn print_banner() {
    println!("{}", "netgap".bold().bright_green());
}
