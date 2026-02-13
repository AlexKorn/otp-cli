use anyhow::Result;

mod cli;
mod commands;
mod parsers;
mod proto;
mod types;

use cli::Cli;

fn main() -> Result<()> {
    Cli::run()
}
