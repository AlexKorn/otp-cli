use anyhow::{Result, anyhow};
use argon2::Argon2;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use cli_clipboard::{ClipboardContext, ClipboardProvider};
use std::fs;
use std::io::{Write, stdin, stdout};
use std::path::PathBuf;
use std::process;
use std::sync::mpsc::channel;
use std::{thread, time};
use termion::{clear, cursor, event::Key, input::TermRead, raw::IntoRawMode};
use toml;
use totp_rs::{Algorithm, TOTP};

use crate::types::{BufferedStdout, KeyFile, TokenAlgorithm, TokenType};

pub fn use_token(key_file: &PathBuf, token_label: &str) -> Result<()> {
    let mut maybe_clipboard = ClipboardContext::new().ok();
    let stdout_handle = stdout().into_raw_mode()?;

    let clean_exit = || -> ! {
        std::mem::drop(stdout_handle);
        process::exit(0);
    };

    let mut stdout = stdout();
    let mut stdin = stdin();

    write!(stdout, "Enter database password: ")?;
    stdout.flush()?;
    let key_file_password = stdin.read_passwd(&mut stdout)?.unwrap_or_default();
    write!(stdout, "\r\n{}{}", cursor::Up(1), clear::AfterCursor)?;
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

    let mut buffered_stdout = BufferedStdout::new(stdout);

    let (sender, receiver) = channel::<AppEvent>();
    let sender_key = sender.clone();

    thread::spawn(move || {
        let stdin = stdin.lock();

        for k in stdin.keys() {
            match k {
                Ok(key) => match key {
                    Key::Char('q') | Key::Esc | Key::Ctrl('c') => {
                        sender_key.send(AppEvent::Terminate).unwrap()
                    }
                    Key::Char('c') => sender_key.send(AppEvent::CopyToClipboard).unwrap(),
                    _ => {}
                },
                Err(_) => sender_key.send(AppEvent::Terminate).unwrap(),
            };
        }
    });

    thread::spawn(move || {
        loop {
            sender.send(AppEvent::Timer).unwrap();
            thread::sleep(time::Duration::from_millis(1000));
        }
    });

    loop {
        let event = match receiver.recv() {
            Ok(evt) => evt,
            Err(_) => {
                buffered_stdout.clear().ok();
                clean_exit()
            }
        };

        match event {
            AppEvent::Terminate => {
                buffered_stdout.clear().ok();
                clean_exit()
            }
            AppEvent::CopyToClipboard => {
                if let Some(clipboard) = maybe_clipboard.as_mut() {
                    let code = totp.generate_current()?;
                    clipboard.set_contents(code).ok();
                }
            }
            AppEvent::Timer => {
                let code = totp.generate_current()?;
                let ttl = totp.ttl()?;

                buffered_stdout.add(&format!(
                    "token: {}\r\ncode: {} ttl: {}\r\n\r\n",
                    token_label, code, ttl
                ));
                buffered_stdout.add("press 'c' to copy code to clipboard,\r\n");
                buffered_stdout.add("press 'q', 'Ctrl+c' or 'Esc' to exit\r\n");
                buffered_stdout.clear()?;
                buffered_stdout.flush()?;
            }
        };
    }
}

enum AppEvent {
    Terminate,
    CopyToClipboard,
    Timer,
}
