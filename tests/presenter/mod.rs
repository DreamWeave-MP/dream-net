//! Presents a connect token from a child process.
//!
//! A connect token admits one connection attempt: once a process has passed a token to
//! `connect`, it refuses that token itself, before any packet. The server's own refusal of a
//! used token is a separate property, and still has to be tested, so a test that needs a used
//! token to reach the server presents it from another process, which has never seen the token,
//! exactly as a second machine or a restarted host would.
//!
//! [`spawn`] starts this test binary again, running only its [`ENTRY`] test with the token and a
//! mode in the environment. That test (each binary that uses this module defines it, calling
//! its own child runner) does nothing in an ordinary run. The child reports what it saw on
//! stdout, one `presenter: ` line each, which [`Presenter::finish`] returns.

#![allow(dead_code)]

use std::fmt::Display;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};

/// The name of the test function each binary using this module defines as the child's entry.
pub const ENTRY: &str = "presenter_child";

const TOKEN_ENV: &str = "DREAM_NET_TEST_PRESENT_TOKEN";
const MODE_ENV: &str = "DREAM_NET_TEST_PRESENT_MODE";
const BIND_ENV: &str = "DREAM_NET_TEST_PRESENT_BIND";
const PREFIX: &str = "presenter: ";

/// A child process presenting a token.
pub struct Presenter {
    child: Child,
}

/// Starts a child process of this test binary that presents `token` in `mode` (the binary's
/// child runner decides what each mode does), from a socket bound to `bind`: an address a
/// client of this process used and has released, to present the token from the same socket
/// address again, or 127.0.0.1 port 0 for a new one.
pub fn spawn(mode: &str, token: &[u8], bind: SocketAddr) -> Presenter {
    let mut hex = String::with_capacity(token.len() * 2);
    for byte in token {
        write!(hex, "{byte:02x}").unwrap();
    }
    let child = Command::new(std::env::current_exe().expect("this test binary"))
        .args(["--exact", ENTRY, "--nocapture", "--test-threads", "1"])
        .env(TOKEN_ENV, hex)
        .env(MODE_ENV, mode)
        .env(BIND_ENV, bind.to_string())
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("starting the presenter child");
    Presenter { child }
}

impl Presenter {
    /// Whether the child is still running.
    pub fn running(&mut self) -> bool {
        self.child
            .try_wait()
            .expect("polling the presenter")
            .is_none()
    }

    /// Waits for the child, requires it to have succeeded, and returns its report lines.
    pub fn finish(self) -> Vec<String> {
        let output = self
            .child
            .wait_with_output()
            .expect("waiting for the presenter");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the presenter child failed ({}):\n{stdout}\n{}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
        let lines: Vec<String> = stdout
            .lines()
            // libtest may print its own `test ... ` in front of the first line
            .filter_map(|line| line.split_once(PREFIX).map(|(_, report)| report))
            .map(str::to_owned)
            .collect();
        assert!(
            lines.iter().any(|line| line == "done"),
            "the presenter child never ran ({ENTRY} was not run?):\n{stdout}"
        );
        lines
    }
}

/// In the child: the mode, token and bind address this process was started to present with,
/// or `None` in an ordinary test run.
pub fn request() -> Option<(String, Vec<u8>, SocketAddr)> {
    let mode = std::env::var(MODE_ENV).ok()?;
    let bind = std::env::var(BIND_ENV)
        .expect("a presenter bind address")
        .parse()
        .expect("a socket address");
    let hex = std::env::var(TOKEN_ENV).expect("a presenter token");
    let token = (0..hex.len())
        .step_by(2)
        .map(|at| u8::from_str_radix(&hex[at..at + 2], 16).expect("hex token"))
        .collect();
    Some((mode, token, bind))
}

/// In the child: reports one line to the parent.
pub fn report(line: impl Display) {
    println!("{PREFIX}{line}");
}
