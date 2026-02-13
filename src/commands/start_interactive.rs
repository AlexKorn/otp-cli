use anyhow::{Result, anyhow};
use argon2::Argon2;
use chacha20poly1305::{KeyInit, XChaCha20Poly1305, XNonce, aead::Aead};
use cli_clipboard::{ClipboardContext, ClipboardProvider};
use std::collections::BTreeMap;
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

const PAGE_SIZE: usize = 5;

pub fn start_interactive(key_file: &PathBuf) -> Result<()> {
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

    let mut encryption_key = [0u8; 32];
    Argon2::default()
        .hash_password_into(
            key_file_password.as_bytes(),
            &key_file.master_key_salt,
            &mut encryption_key,
        )
        .map_err(|err| anyhow!("{}", err))?;

    let cipher = XChaCha20Poly1305::new_from_slice(encryption_key.as_slice())?;

    let mut tokens = BTreeMap::new();

    for (token_name, token) in key_file.tokens.iter() {
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

        tokens.insert(token_name.to_owned(), totp);
    }

    let mut buffered_stdout = BufferedStdout::new(stdout);

    let (sender, receiver) = channel::<AppEvent>();
    let sender_key = sender.clone();

    thread::spawn(move || {
        let stdin = stdin.lock();

        for k in stdin.keys() {
            match k {
                Ok(k) => sender_key.send(AppEvent::Key(k)).unwrap(),
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

    let mut name_buf = String::new();
    let mut render_mode = RenderMode::TokensList { page: 0 };

    render_token_list(&tokens, &mut buffered_stdout, &name_buf, 0)?;

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
            AppEvent::Timer => {
                if let RenderMode::Token { ref name, token } = render_mode {
                    render_token(name.as_str(), token, &mut buffered_stdout)?;
                } else {
                }
            }
            AppEvent::Key(key) => match render_mode {
                RenderMode::TokensList { page } => {
                    match key {
                        Key::Esc | Key::Ctrl('c') => {
                            buffered_stdout.clear().ok();
                            clean_exit()
                        }
                        Key::Delete | Key::Ctrl('d') => {
                            name_buf = String::new();
                            render_token_list(&tokens, &mut buffered_stdout, &name_buf, page)?;
                        }
                        Key::Left => {
                            if page != 0 {
                                render_mode = RenderMode::TokensList { page: page - 1 };
                                render_token_list(
                                    &tokens,
                                    &mut buffered_stdout,
                                    &name_buf,
                                    page - 1,
                                )?;
                            }
                        }
                        Key::Right => {
                            if page < tokens.len().div_ceil(PAGE_SIZE) - 1 {
                                render_mode = RenderMode::TokensList { page: page + 1 };
                                render_token_list(
                                    &tokens,
                                    &mut buffered_stdout,
                                    &name_buf,
                                    page + 1,
                                )?;
                            }
                        }
                        Key::Char('\n') => {
                            if name_buf.is_empty() {
                                continue;
                            }

                            if let Ok(index) = name_buf.parse::<usize>()
                                && index < tokens.len()
                            {
                                let token_name = tokens.keys().skip(index).next().unwrap().clone();
                                let token = tokens.get(token_name.as_str()).unwrap();
                                name_buf = String::new();
                                render_token(token_name.as_str(), token, &mut buffered_stdout)?;

                                render_mode = RenderMode::Token {
                                    name: token_name,
                                    token,
                                };
                            } else if let Some(token) = tokens.get(name_buf.as_str()) {
                                render_token(name_buf.as_str(), token, &mut buffered_stdout)?;

                                render_mode = RenderMode::Token {
                                    name: std::mem::take(&mut name_buf),
                                    token,
                                };
                            } else {
                                render_token_list(&tokens, &mut buffered_stdout, &name_buf, page)?;
                            }
                        }
                        Key::Backspace => {
                            name_buf.pop();
                            render_token_list(&tokens, &mut buffered_stdout, &name_buf, page)?;
                        }
                        Key::Char(ch) => {
                            name_buf.push(ch);
                            render_token_list(&tokens, &mut buffered_stdout, &name_buf, page)?;
                        }
                        _ => {}
                    };
                }
                RenderMode::Token { name: _, token } => match key {
                    Key::Esc | Key::Ctrl('c') => {
                        buffered_stdout.clear().ok();
                        clean_exit()
                    }
                    Key::Char('c') => {
                        if let Some(clipboard) = maybe_clipboard.as_mut() {
                            let code = token.generate_current()?;
                            clipboard.set_contents(code).ok();
                        }
                    }
                    Key::Char('q') => {
                        render_mode = RenderMode::TokensList { page: 0 };
                        render_token_list(&tokens, &mut buffered_stdout, &name_buf, 0)?;
                    }
                    _ => {}
                },
            },
        };
    }
}

fn render_token_list(
    tokens: &BTreeMap<String, TOTP>,
    buffered_stdout: &mut BufferedStdout,
    name_buffer: &str,
    page: usize,
) -> Result<()> {
    let paging_required = PAGE_SIZE < tokens.len();

    if paging_required {
        buffered_stdout.add(&format!(
            "Total tokens amount: {}, showing page {} of {}\r\n\r\n",
            tokens.len(),
            page + 1,
            tokens.len().div_ceil(PAGE_SIZE)
        ));
    } else {
        buffered_stdout.add(&format!("Total tokens amount: {}\r\n\r\n", tokens.len(),));
    }

    for (index, (token_name, _)) in tokens
        .iter()
        .enumerate()
        .skip(page * PAGE_SIZE)
        .take(PAGE_SIZE)
    {
        buffered_stdout.add(&format!("   [{index}] {token_name}\r\n"));
    }

    buffered_stdout.add("\r\n");

    if paging_required {
        buffered_stdout.add("use left and right arrows to navigate between pages,\r\n");
    }

    buffered_stdout
        .add("press 'Ctrl+c' or 'Esc' to exit,\r\npress 'Ctrl+d' or 'Del' to clear input.\r\n");

    buffered_stdout.add(&format!(
        "Enter token index or name to show code: {}\r\n",
        name_buffer,
    ));

    buffered_stdout.clear()?;
    buffered_stdout.flush()?;

    Ok(())
}

fn render_token(name: &str, token: &TOTP, buffered_stdout: &mut BufferedStdout) -> Result<()> {
    let code = token.generate_current()?;
    let ttl = token.ttl()?;

    buffered_stdout.add(&format!(
        "token: {}\r\ncode: {} ttl: {}\r\n\r\n",
        name, code, ttl
    ));

    buffered_stdout.add("press 'c' to copy code to clipboard,\r\n");
    buffered_stdout.add("press 'q' to return to token list,\r\n");
    buffered_stdout.add("press 'Ctrl+c' or 'Esc' to exit\r\n");

    buffered_stdout.clear()?;
    buffered_stdout.flush()?;

    Ok(())
}

enum AppEvent {
    Timer,
    Key(Key),
    Terminate,
}

enum RenderMode<'a> {
    TokensList { page: usize },
    Token { name: String, token: &'a TOTP },
}
