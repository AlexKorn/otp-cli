use anyhow::{Result, anyhow};
use clap::{CommandFactory, Parser, Subcommand};
use std::path::PathBuf;

use crate::{commands::*, types::BackupType};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
pub struct Cli {
    /// Path to database with encrypted tokens (required for all commands except `parse`)
    keyfile: Option<PathBuf>,
    /// Command
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
    /// Convert backup file to own file format (if existing database specified, tokens will be appended)
    Convert {
        /// Backup type (depends on authenticator)
        #[arg(short = 't', long = "type", value_name = "TYPE")]
        backup_type: BackupType,
        /// Path to backup file
        #[arg(short, long, value_name = "FILE")]
        input: PathBuf,
    },
    /// Add token to database from otpauth url
    Add {
        /// Token name
        #[arg(short = 'n', long, value_name = "NAME")]
        name: String,
        /// Token otpauth url
        #[arg(short = 'u', long, value_name = "OTPAUTH URL")]
        url: String,
    },
    /// Use token from specified database
    Use {
        /// Token name
        #[arg(short, long, value_name = "TOKEN")]
        token: String,
    },
    /// Starts app in interactive mode
    Start,
}

impl Cli {
    pub fn run() -> Result<()> {
        let cli = Cli::parse();

        let maybe_keyfile = cli.keyfile.as_ref();

        match &cli.command {
            Some(Commands::Parse { backup_type, file }) => parse_backup_file(backup_type, file),
            Some(Commands::Convert { backup_type, input }) => {
                let keyfile = maybe_keyfile
                    .ok_or(anyhow!("Key file must be specified for `convert` command"))?;
                convert_backup_file(backup_type, input, keyfile)
            }
            Some(Commands::Add { name, url }) => {
                let keyfile =
                    maybe_keyfile.ok_or(anyhow!("Key file must be specified for `add` command"))?;
                add_token(keyfile, name.to_owned(), url)
            }
            Some(Commands::Use { token }) => {
                let keyfile =
                    maybe_keyfile.ok_or(anyhow!("Key file must be specified for `use` command"))?;
                use_token(keyfile, token.as_str())
            }
            Some(Commands::Start) => {
                let keyfile = maybe_keyfile
                    .ok_or(anyhow!("Key file must be specified for `start` command"))?;
                start_interactive(keyfile)
            }
            None => {
                Cli::command().print_help().ok();
                Ok(())
            }
        }
    }
}
