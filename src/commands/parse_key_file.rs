use anyhow::Result;
use std::io::{stdin, stdout, Write};
use std::path::PathBuf;
use termion::input::TermRead;

use crate::{enums::BackupType, parsers::*};

pub fn parse_key_file(backup_type: &BackupType, backup_file: &PathBuf) -> Result<()> {
    let stdout = stdout();
    let mut stdout = stdout.lock();
    let stdin = stdin();
    let mut stdin = stdin.lock();

    let tokens = match backup_type {
        BackupType::NewToken => {
            stdout.write_all(b"parsing backup...\n")?;
            stdout.flush().unwrap();

            parse_new_token(backup_file)
        }
        BackupType::FreeOtp => {
            stdout.write_all(b"Enter backup file password: ")?;
            stdout.flush().unwrap();
            let input_password = stdin.read_passwd(&mut stdout)?.unwrap();
            stdout.write_all(b"\nparsing backup...\n")?;
            stdout.flush().unwrap();

            parse_freeotp_backup(backup_file, input_password.as_str())
        }
        BackupType::GoogleAuth => {
            stdout.write_all(b"parsing backup...\n")?;
            stdout.flush().unwrap();

            parse_googleauth_backup(backup_file)
        }
    }?;

    std::mem::drop(stdout);

    println!("Tokens:\n{:#?}", tokens);
    Ok(())
}
