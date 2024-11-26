use anyhow::{anyhow, Result};
use argon2::Argon2;
use chacha20poly1305::{aead::Aead, KeyInit, XChaCha20Poly1305, XNonce};
use std::fs;
use std::io::{stdin, stdout, Write};
use std::path::PathBuf;
use std::process;
use std::{thread, time};
use termion::{
    clear,
    cursor::{self, DetectCursorPos},
    event::Key,
    input::TermRead,
    raw::IntoRawMode,
    terminal_size,
};
use toml;
use totp_rs::{Algorithm, TOTP};

use crate::{
    enums::{TokenAlgorithm, TokenType},
    types::KeyFile,
};

const PRINTED_LINES: u16 = 3; // Amount of lines printed with token info

pub fn use_token(key_file: &PathBuf, token_label: &str) -> Result<()> {
    let mut stdout_handle = stdout().into_raw_mode()?;
    let mut stdout = stdout();
    let mut stdin = stdin();

    // write!(stdout, "{}", cursor::Save)?;
    stdout.flush()?;
    let mut cursor_position = stdout
        .cursor_pos()
        .expect("Failed to get cursor position from stdout");
    let term_size = terminal_size().expect("Failed to get terminal size");

    if (term_size.1 - cursor_position.1) < PRINTED_LINES {
        cursor_position.1 -= PRINTED_LINES - (term_size.1 - cursor_position.1);
    }

    write!(stdout, "Enter key file password: ")?;
    stdout.flush()?;
    let key_file_password = stdin.read_passwd(&mut stdout)?.unwrap_or_default();
    write!(stdout, "\r\n\r\n\r\n")?; // Padding for correct cursor movement - equals to PRINTED_LINES
    stdout.flush()?;

    let key_file_data = fs::read_to_string(key_file)?;
    let key_file = toml::from_str::<KeyFile>(key_file_data.as_str())?;

    let token = key_file
        .tokens
        .get(token_label)
        .ok_or(anyhow!("Token {} not found in file", token_label))?;

    let mut encryption_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(
            key_file_password.as_bytes(),
            &key_file.master_key_salt,
            &mut encryption_key,
        )
        .map_err(|err| anyhow!("{}", err))?;

    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_slice())?;

    let decrypted_token_key = cipher
        .decrypt(XNonce::from_slice(&token.key[0..24]), &token.key[24..])
        .map_err(|err| anyhow!("Failed to decrypt token key: {}", err))?;

    let algorithm = match token.algorithm {
        TokenAlgorithm::Sha1 => Algorithm::SHA1,
        TokenAlgorithm::Sha256 => Algorithm::SHA256,
        TokenAlgorithm::Sha512 => Algorithm::SHA512,
    };

    if token.token_type != TokenType::Totp {
        Err(anyhow!(
            "This token type is not supported yet: {:?}",
            token.token_type
        ))?;
    }

    let totp = TOTP::new_unchecked(
        algorithm,
        token.digits as usize,
        1,
        token.period,
        decrypted_token_key.clone(),
        Some(token.issuer.clone()),
        token.label.clone(),
    );

    thread::spawn(move || {
        let stdin = stdin.lock();

        let clean_exit = move || {
            write!(
                stdout_handle,
                "{}{}",
                cursor::Goto(cursor_position.0, cursor_position.1),
                clear::AfterCursor
            )
            .unwrap();
            stdout_handle.flush().unwrap();
            std::mem::drop(stdout_handle);
            process::exit(0);
        };

        if stdin
            .keys()
            .find(|k| match k.as_ref().unwrap() {
                Key::Char('q') => true,
                Key::Esc => true,
                Key::Ctrl('c') => true,
                _ => false,
            })
            .is_some()
        {
            clean_exit();
        }
    });

    loop {
        let code = totp.generate_current()?;
        let ttl = totp.ttl()?;

        write!(
            stdout,
            "{}{}",
            cursor::Goto(cursor_position.0, cursor_position.1),
            clear::AfterCursor
        )
        .unwrap();
        stdout.flush()?;
        write!(
            stdout,
            "token: {}\r\ncode: {} ttl: {}\r\n",
            token_label, code, ttl
        )?;
        write!(stdout, "press 'q', 'Ctrl+c' or 'Esc' to exit\r\n",)?;
        stdout.flush()?;
        thread::sleep(time::Duration::from_millis(1000));
    }
}
