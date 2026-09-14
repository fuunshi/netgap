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

use netgap_assess::{FtpServer, MongoServer, RedisServer, SnmpServer};
use netgap_core::Device;
use netgap_probes::ftp;
use netgap_probes::mongo;
use netgap_probes::redis::{self, Access};
use netgap_probes::snmp;
use std::net::IpAddr;
use tokio::task::JoinSet;

/// The port each service is checked on.
const FTP_PORT: u16 = 21;
const REDIS_PORT: u16 = 6379;
const MONGO_PORT: u16 = 27017;

/// SNMP is asked over UDP, so the port scanner never reports it open: every
/// device is offered the question instead.
const SNMP_PORT: u16 = 161;

/// How many services to question at once.
const CONCURRENCY: usize = 16;

/// What one device answered.
enum Answer {
    Ftp(ftp::FtpLogin),
    Redis(Access),
    Mongo(mongo::Access),
    Snmp(snmp::Access),
}

/// Ask the services the scan found, and every device for SNMP.
pub async fn check(devices: &mut [Device]) {
    let mut targets: Vec<(usize, IpAddr, u16)> = devices
        .iter()
        .enumerate()
        .flat_map(|(index, device)| {
            let ip = device.ip;
            [FTP_PORT, REDIS_PORT, MONGO_PORT]
                .into_iter()
                .filter(|port| device.open_ports.contains(port))
                .map(move |port| (index, ip, port))
        })
        .collect();

    // SNMP listens on UDP, which the port scan does not cover, so its
    // presence is decided by asking rather than by looking.
    targets.extend(
        devices
            .iter()
            .enumerate()
            .map(|(index, device)| (index, device.ip, SNMP_PORT)),
    );

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
                    MONGO_PORT => mongo::inspect(ip, port).await.ok().map(Answer::Mongo),
                    SNMP_PORT => snmp::inspect(ip, port).await.ok().map(Answer::Snmp),
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
            Answer::Mongo(access) => {
                let server = MongoServer {
                    open: access == mongo::Access::Open,
                };
                (
                    netgap_assess::mongo_findings(device.ip, port, &server),
                    "a login is required",
                )
            }
            Answer::Snmp(access) => {
                let server = SnmpServer {
                    public_community: matches!(access, snmp::Access::Open { .. }),
                    description: match access {
                        snmp::Access::Open { description } => description,
                        snmp::Access::Silent => None,
                    },
                };
                (
                    netgap_assess::snmp_findings(device.ip, port, &server),
                    "did not answer the public community",
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
        assert_eq!(MONGO_PORT, 27017);
        assert_eq!(SNMP_PORT, 161);
    }
}
