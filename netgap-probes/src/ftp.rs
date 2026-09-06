//! Whether an FTP server lets anyone in.
//!
//! Anonymous FTP is a setting, not a bug: the administrator chose to allow the
//! user name `anonymous` with any password at all, usually to publish files.
//! What it means depends on the permissions behind it, and this cannot tell —
//! but an anonymous login that succeeds is the difference between "FTP is
//! reachable" and "FTP will hand files to anyone who connects", so it is worth
//! knowing which of the two a network has.
//!
//! The login uses the `anonymous` user with an address as the password, which
//! is exactly what an anonymous client sends. No other account is tried and no
//! password is guessed.

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(3);

/// The password an anonymous login carries. Convention is an address.
const ANONYMOUS_PASSWORD: &str = "netgap@localhost";

/// What the server said to an anonymous login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FtpLogin {
    /// The banner the server opened with, if it sent one.
    pub banner: Option<String>,
    /// The server let the anonymous user in.
    pub anonymous: bool,
}

/// Try the anonymous login.
pub async fn inspect(ip: IpAddr, port: u16) -> Result<FtpLogin> {
    let stream = timeout(TIMEOUT, TcpStream::connect(SocketAddr::new(ip, port)))
        .await
        .map_err(|_| anyhow!("connecting to {ip}:{port} timed out"))??;
    let mut server = BufReader::new(stream);

    let (code, text) = read_reply(&mut server)
        .await
        .ok_or_else(|| anyhow!("{ip}:{port} did not send an FTP greeting"))?;
    if code != 220 {
        bail!("{ip}:{port} answered {code}, which is not an FTP greeting");
    }
    let banner = Some(text);

    let (code, _) = command(&mut server, "USER anonymous").await?;
    let anonymous = match code {
        // Already in: this server does not want a password at all.
        230 => true,
        331 => {
            let (code, _) = command(&mut server, &format!("PASS {ANONYMOUS_PASSWORD}")).await?;
            code == 230
        }
        _ => false,
    };

    // Leave politely, whatever the answer was.
    let _ = server.write_all(b"QUIT\r\n").await;
    let _ = server.flush().await;

    Ok(FtpLogin { banner, anonymous })
}

/// Send one command and read its reply.
async fn command(server: &mut BufReader<TcpStream>, line: &str) -> Result<(u16, String)> {
    server.write_all(format!("{line}\r\n").as_bytes()).await?;
    server.flush().await?;
    read_reply(server)
        .await
        .ok_or_else(|| anyhow!("the server closed the connection after '{line}'"))
}

/// Read one reply, joining a multi-line reply into a single string.
async fn read_reply(server: &mut BufReader<TcpStream>) -> Option<(u16, String)> {
    let first = read_line(server).await?;
    let code = reply_code(&first)?;
    let mut text = first.clone();

    // A multi-line reply marks its middle lines with a hyphen: "211-Features".
    if first.as_bytes().get(3) == Some(&b'-') {
        let terminator = format!("{code} ");
        loop {
            let line = read_line(server).await?;
            let done = line.starts_with(&terminator);
            text.push_str(&line);
            if done {
                break;
            }
        }
    }

    Some((code, text.trim_end().to_string()))
}

/// One line without its line ending.
async fn read_line(server: &mut BufReader<TcpStream>) -> Option<String> {
    let mut line = String::new();
    let read = timeout(TIMEOUT, server.read_line(&mut line))
        .await
        .ok()?
        .ok()?;
    if read == 0 {
        return None;
    }
    Some(line)
}

/// The three-digit code a reply opens with.
pub fn reply_code(line: &str) -> Option<u16> {
    let code = line.get(..3)?;
    if code.bytes().all(|byte| byte.is_ascii_digit()) {
        code.parse().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn reply_codes_are_the_first_three_digits() {
        assert_eq!(reply_code("220 Welcome"), Some(220));
        assert_eq!(reply_code("331-\r\n"), Some(331));
        assert_eq!(reply_code("220"), Some(220));
        assert_eq!(reply_code("2x0 Welcome"), None);
        assert_eq!(reply_code("22"), None);
        assert_eq!(reply_code(""), None);
    }

    /// A server that greets with `replies[0]` and then answers each command
    /// with the next reply.
    async fn serve(replies: &[&str]) -> (IpAddr, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");
        let replies: Vec<String> = replies.iter().map(|reply| reply.to_string()).collect();

        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let mut server = BufReader::new(stream);
            for (index, reply) in replies.iter().enumerate() {
                if index > 0 {
                    // Each later reply follows a command.
                    let mut command = String::new();
                    if server.read_line(&mut command).await.is_err() {
                        return;
                    }
                }
                if server.write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
                let _ = server.flush().await;
            }
            // Hold the connection open so the client's QUIT is not a write to
            // a closed socket.
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        (address.ip(), address.port())
    }

    #[tokio::test]
    async fn an_anonymous_login_that_succeeds_is_reported() {
        let (ip, port) = serve(&[
            "220 Hello\r\n",
            "331 Give a password\r\n",
            "230 Logged in\r\n",
        ])
        .await;

        let login = inspect(ip, port).await.expect("inspect");
        assert!(login.anonymous);
        assert_eq!(login.banner.as_deref(), Some("220 Hello"));
    }

    #[tokio::test]
    async fn a_refused_anonymous_login_is_not_reported() {
        let (ip, port) = serve(&[
            "220 Hello\r\n",
            "331 Give a password\r\n",
            "530 Login incorrect\r\n",
        ])
        .await;

        let login = inspect(ip, port).await.expect("inspect");
        assert!(!login.anonymous);
    }

    #[tokio::test]
    async fn a_server_that_skips_the_password_is_still_anonymous() {
        let (ip, port) = serve(&["220 Hello\r\n", "230 Logged in\r\n"]).await;

        let login = inspect(ip, port).await.expect("inspect");
        assert!(login.anonymous);
    }

    #[tokio::test]
    async fn a_service_that_is_not_ftp_is_an_error() {
        let (ip, port) = serve(&["SSH-2.0-OpenSSH 8.9\r\n"]).await;
        assert!(inspect(ip, port).await.is_err());
    }
}
