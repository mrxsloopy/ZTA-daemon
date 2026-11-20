#![warn(clippy::pedantic)]
use zta_policy::{Policy, Role, Sensitivity, ActionKind, Honeypot};
use serde::Deserialize;
use std::{collections::HashMap, fs};

// --- Config structures ---
#[derive(Debug, Deserialize)]
pub struct PolicyConfig {
    pub max_failed_attempts: u32,
    pub honeypot: Honeypot,
    pub rules: Vec<RuleEntry>,
}

#[derive(Debug, Deserialize)]
pub struct RuleEntry {
    pub role: Role,
    pub sensitivity: Sensitivity,
    pub action: ActionKind,
    pub ttl: u64,
}

// --- Configurations Errors ---
#[derive(Debug)]
#[allow(dead_code)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

// Processing pattern (so nasty)
impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(err) => write!(f, "file reading error: {err}"),
            ConfigError::Parse(err) => write!(f, "TOML parsing error: {err}"),
        }
    }
}

impl std::error::Error for ConfigError {}   // use all standard

impl From<std::io::Error> for ConfigError {
    fn from(err: std::io::Error) -> Self { ConfigError::Io(err) }
}
impl From<toml::de::Error> for ConfigError {
    fn from(err: toml::de::Error) -> Self { ConfigError::Parse(err) }
}
 
// --- Loading from file ---
#[allow(dead_code)]
pub fn load_policy(path: &str) -> Result<Policy, ConfigError> {
    let content: String = fs::read_to_string(path)?;
    let config: PolicyConfig = toml::from_str(&content)?;
    Ok(config.into())
}

// --- Deserialization (main block) ---
impl From<PolicyConfig> for Policy {
    fn from(config: PolicyConfig) -> Self {
        let mut rules = HashMap::new();
        for rule in config.rules {
            rules.insert((rule.role, rule.sensitivity, rule.action), rule.ttl);
        }
        Policy::new(rules, config.honeypot, config.max_failed_attempts)
    }
}
