//! Whether a Redis server will talk to anyone who connects.
//!
//! Redis ships with no password and, until recently, listened on every
//! interface. An unauthenticated Redis is not merely a data store someone can
//! read: its own administration commands can write a file anywhere the process
//! can write, which is a well-worn path to running code on the host.
//!
//! `PING` is the cheapest question that distinguishes the two states: an open
//! server answers `+PONG`, and a protected one answers `-NOAUTH`. Nothing here
//! writes, and nothing here guesses a password.

use anyhow::{anyhow, bail, Result};
use std::net::{IpAddr, SocketAddr};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

const TIMEOUT: Duration = Duration::from_secs(3);

/// How much of a reply to read. `INFO` is the largest thing asked for.
const MAX_REPLY: usize = 64 * 1024;

/// What the server allows without a password.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Access {
    /// The server answered without asking for credentials.
    Open {
        /// The version, when `INFO` was answered too.
        version: Option<String>,
    },
    /// The server refused until authenticated.
    Protected,
}

/// Ask whether the server needs a password.
pub async fn inspect(ip: IpAddr, port: u16) -> Result<Access> {
    let mut stream = timeout(TIMEOUT, TcpStream::connect(SocketAddr::new(ip, port)))
        .await
        .map_err(|_| anyhow!("connecting to {ip}:{port} timed out"))??;

    let reply = ask(&mut stream, "PING").await?;
    if reply.starts_with("-NOAUTH") || reply.starts_with("-NOPERM") {
        return Ok(Access::Protected);
    }
    if !reply.starts_with("+PONG") {
        // "ERR unknown command" and friends mean this is not Redis, or not a
        // Redis that answers the question. Either way, no verdict.
        bail!("{ip}:{port} did not answer PING like a Redis server");
    }

    // The version turns a port number into something a person can act on.
    let version = match ask(&mut stream, "INFO server").await {
        Ok(info) => version_of(&info),
        Err(_) => None,
    };

    Ok(Access::Open { version })
}

/// Send one inline command and read the reply.
async fn ask(stream: &mut TcpStream, command: &str) -> Result<String> {
    stream
        .write_all(format!("{command}\r\n").as_bytes())
        .await?;
    stream.flush().await?;

    let mut reply = vec![0u8; MAX_REPLY];
    let read = timeout(TIMEOUT, stream.read(&mut reply))
        .await
        .map_err(|_| anyhow!("the server did not reply to {command}"))??;
    if read == 0 {
        bail!("the server closed the connection after {command}");
    }
    reply.truncate(read);
    Ok(String::from_utf8_lossy(&reply).into_owned())
}

/// The `redis_version` field of an `INFO` reply.
pub fn version_of(info: &str) -> Option<String> {
    info.lines()
        .find_map(|line| line.strip_prefix("redis_version:"))
        .map(|version| version.trim().to_string())
        .filter(|version| !version.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncBufReadExt, BufReader};
    use tokio::net::TcpListener;

    /// A server that answers each command with the next reply.
    async fn serve(replies: &'static [&'static str]) -> (IpAddr, u16) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let address = listener.local_addr().expect("address");

        tokio::spawn(async move {
            let Ok((stream, _)) = listener.accept().await else {
                return;
            };
            let mut server = BufReader::new(stream);
            for reply in replies {
                let mut command = String::new();
                if server.read_line(&mut command).await.is_err() {
                    return;
                }
                if server.write_all(reply.as_bytes()).await.is_err() {
                    return;
                }
                let _ = server.flush().await;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        });

        (address.ip(), address.port())
    }

    #[test]
    fn the_version_is_read_from_an_info_reply() {
        let info = "# Server\r\nredis_version:7.2.4\r\nredis_git_sha1:00000000\r\n";
        assert_eq!(version_of(info).as_deref(), Some("7.2.4"));
        assert_eq!(version_of("# Server\r\n"), None);
    }

    #[tokio::test]
    async fn a_pong_means_no_password_is_needed() {
        let (ip, port) = serve(&[
            "+PONG\r\n",
            "$59\r\n# Server\r\nredis_version:6.0.16\r\nos:Linux\r\nprocess_id:1\r\n\r\n",
        ])
        .await;

        assert_eq!(
            inspect(ip, port).await.expect("inspect"),
            Access::Open {
                version: Some("6.0.16".into())
            }
        );
    }

    #[tokio::test]
    async fn noauth_means_the_server_is_protected() {
        let (ip, port) = serve(&["-NOAUTH Authentication required.\r\n"]).await;
        assert_eq!(inspect(ip, port).await.expect("inspect"), Access::Protected);
    }

    #[tokio::test]
    async fn something_else_on_the_port_is_an_error() {
        let (ip, port) = serve(&["HTTP/1.1 400 Bad Request\r\n"]).await;
        assert!(inspect(ip, port).await.is_err());
    }
}
