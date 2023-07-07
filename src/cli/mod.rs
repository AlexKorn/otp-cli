use anyhow::Result;
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

use crate::{commands::*, enums::BackupType};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Parse authenticator backup file & print tokens to stdout
    Parse {
        /// Backup type (depends on authenticator)
        #[arg(short = 't', long = "type", value_name = "TYPE")]
        backup_type: BackupType,
        /// Path to backup file
        #[arg(short, long, value_name = "FILE")]
        file: PathBuf,
    },
    /// Convert backup file to own file format
    Convert {
        /// Backup type (depends on authenticator)
        #[arg(short = 't', long = "type", value_name = "TYPE")]
        backup_type: BackupType,
        /// Path to backup file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,
        /// Path to output key file
        #[arg(short, long, value_name = "FILE")]
        output: PathBuf,
    },
    /// Use token from own key file
    Use {
        /// Path to key file in format
        #[arg(short, long, value_name = "FILE")]
        keyfile: PathBuf,
        /// Token name
        #[arg(short, long, value_name = "TOKEN")]
        token: String,
    },
}

impl Cli {
    pub fn run() -> Result<()> {
        let cli = Cli::parse();

        match &cli.command {
            Some(Commands::Parse { backup_type, file }) => parse_key_file(backup_type, file),
            Some(Commands::Convert {
                backup_type,
                input,
                output,
            }) => convert_key_file(backup_type, input, output),
            Some(Commands::Use { keyfile, token }) => use_token(keyfile, token.as_str()),
            None => {
                Cli::command().print_help().ok();
                Ok(())
            }
        }
    }
}
