use anyhow::Result;
use std::io::{Stdout, Write};
use termion::{clear, cursor};

pub struct BufferedStdout {
    stdout: Stdout,
    buffer: String,
    printed_lines: u16,
}

impl BufferedStdout {
    pub fn new(stdout: Stdout) -> Self {
        Self {
            stdout,
            buffer: String::new(),
            printed_lines: 0,
        }
    }

    pub fn add(&mut self, s: &str) {
        self.buffer.push_str(s);
    }

    pub fn flush(&mut self) -> Result<()> {
        if !self.buffer.ends_with("\r\n") {
            self.buffer.push_str("\r\n");
        }
        self.printed_lines += self.buffer.lines().count() as u16;
        write!(self.stdout, "{}", self.buffer)?;
        self.buffer = String::new();
        self.stdout.flush()?;
        Ok(())
    }

    pub fn clear(&mut self) -> Result<()> {
        if self.printed_lines > 0 {
            write!(
                self.stdout,
                "{}{}",
                cursor::Up(self.printed_lines),
                clear::AfterCursor
            )?;
            self.stdout.flush()?;
        }
        self.printed_lines = 0;
        Ok(())
    }
}
