use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanSummary {
    pub interface: String,
    pub mode: ScanMode,
    pub hosts: Vec<HostReport>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostReport {
    pub ip: String,
    pub hostname: Option<String>,
    pub mac: Option<String>,
    pub open_ports: Vec<PortFinding>,
    pub gaps: Vec<GapFinding>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortFinding {
    pub port: u16,
    pub protocol: String,
    pub service: Option<String>,
    pub banner: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GapFinding {
    pub severity: Severity,
    pub title: String,
    pub description: String,
    pub recommendation: String,
    pub port: Option<u16>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ScanMode {
    Quick,
    Full,
}
