//! Services that will talk to anyone who connects.
//!
//! An open port says a service is listening. It does not say what happens next:
//! some services greet the first stranger with a banner and then ask for a
//! password, and some simply do the work. The difference is invisible from the
//! port alone and is usually the whole question — an anonymous FTP server and
//! a password-protected one look identical in a port list.
//!
//! Each check here is the smallest exchange that separates the two, on the
//! service's own protocol. None of them guesses a password or tries more than
//! the default door.

use netgap_assess::{FtpServer, RedisServer};
use netgap_core::Device;
use netgap_probes::ftp;
use netgap_probes::redis::{self, Access};
use std::net::IpAddr;
use tokio::task::JoinSet;

/// The port each service is checked on.
const FTP_PORT: u16 = 21;
const REDIS_PORT: u16 = 6379;

/// How many services to question at once.
const CONCURRENCY: usize = 8;

/// What one device answered.
enum Answer {
    Ftp(ftp::FtpLogin),
    Redis(Access),
}

/// Ask every FTP and Redis server the scan found.
pub async fn check(devices: &mut [Device]) {
    let targets: Vec<(usize, IpAddr, u16)> = devices
        .iter()
        .enumerate()
        .flat_map(|(index, device)| {
            let ip = device.ip;
            [FTP_PORT, REDIS_PORT]
                .into_iter()
                .filter(|port| device.open_ports.contains(port))
                .map(move |port| (index, ip, port))
        })
        .collect();

    if targets.is_empty() {
        return;
    }

    eprintln!();
    eprintln!("Services without credentials");
    eprintln!("────────────────────────────");

    let mut results: Vec<(usize, u16, Option<Answer>)> = Vec::new();
    for chunk in targets.chunks(CONCURRENCY) {
        let mut set = JoinSet::new();
        for (index, ip, port) in chunk {
            let (index, ip, port) = (*index, *ip, *port);
            set.spawn(async move {
                let answer = match port {
                    FTP_PORT => ftp::inspect(ip, port).await.ok().map(Answer::Ftp),
                    _ => redis::inspect(ip, port).await.ok().map(Answer::Redis),
                };
                (index, port, answer)
            });
        }
        while let Some(joined) = set.join_next().await {
            if let Ok(result) = joined {
                results.push(result);
            }
        }
    }

    results.sort_by_key(|(index, _, _)| *index);

    for (index, port, answer) in results {
        // A port that will not speak the protocol is running something else.
        let Some(answer) = answer else {
            continue;
        };

        let device = &mut devices[index];
        let (findings, note) = match answer {
            Answer::Ftp(login) => {
                let server = FtpServer {
                    banner: login.banner.clone(),
                    anonymous: login.anonymous,
                };
                (
                    netgap_assess::ftp_findings(device.ip, port, &server),
                    "no anonymous access",
                )
            }
            Answer::Redis(access) => {
                let server = RedisServer {
                    open: matches!(access, Access::Open { .. }),
                    version: match access {
                        Access::Open { version } => version,
                        Access::Protected => None,
                    },
                };
                (
                    netgap_assess::redis_findings(device.ip, port, &server),
                    "a password is required",
                )
            }
        };

        if findings.is_empty() {
            eprintln!("  ✓ {}:{} — {}", device.ip, port, note);
        }

        for finding in findings {
            eprintln!(
                "  {}:{} [{}] {}",
                device.ip, port, finding.severity, finding.title
            );
            device.add_finding(finding);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_the_services_are_asked_on_their_default_ports() {
        assert_eq!(FTP_PORT, 21);
        assert_eq!(REDIS_PORT, 6379);
    }
}
