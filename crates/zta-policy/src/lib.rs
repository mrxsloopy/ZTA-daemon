//--- PDP-core ---
#![warn(clippy::pedantic)]
use std::{collections::HashMap, future::PollFn};

// --- main struct Subject ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Subject {
    pub id: String,
    pub role: Role,
    pub cert: CertStatus,
}

// --- main struct AccessRequest ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessRequest {
    pub subject: Subject,
    pub resource: Resource,
    pub context: RequestContext,
}

// --- Role ---
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Role {
    Admin,
    Contractor,
    ServiceAccount,
    Employee,
}

// --- Certificate status ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CertStatus {
    Valid {
        expires_in_secs: u64,  // How much is left
        fingerprint: String,
        trusted_ca: String,
        //allowed_scope: Vec<String>, realized in evaulate
    },
    Expired { expired_at: u64, reason: String },  /// Unix timestamp
    Revoked { revoked_at: u64, reason: String },
    Unknown,
}

// --- Fictitious resource  ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Resource {
    pub name: String,
    pub sensitivity: Sensitivity,
}

// --- Authorization Context ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestContext {
    pub action: ActionKind,
    pub request_id: String,
    pub risk_signal: RiskSignal,
    /*pub source_ip: IpAddr, maybe in future
    pub mfa_status: bool,
    pub geo_location: GeoLocation,
    pub device_context: DevicePosture,
    */
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskSignal {
    Normal,
    RepeatedFailures { count: u32 }
}

// --- Sensitivity to a specific resource ---
#[derive(Debug, Clone, PartialEq, Hash, Eq)]
pub enum Sensitivity {
    Public,
    Internal,
    Critical,
}

// --- Subjects actions ---
#[derive(Debug, Clone, Copy, PartialEq, Hash, Eq)]
pub enum ActionKind {
    Read,
    Write,
    Delete,
    Execute,
}

/// --- Decision of PDP (then sent to PEP)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow { ttl_secs: u64, auth_level: AuthLevel },
    Deny { reason: DenyReason },
    Redirect { honeypot: Honeypot, reason: DenyReason },   // honeypot redirect
}

// --- Authorization ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthLevel {
    SingleFactor,
    MultiFactor,
}

// --- Rejection message (reason to SOC) ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DenyReason {
    SuspiciousActivity,
    InvalidCert,
    RoleActionMismatch,
}

impl DenyReason {
    pub fn message(&self) -> &'static str {
        match self {
            DenyReason::SuspiciousActivity => "Suspicious activity!",
            DenyReason::InvalidCert => "Invalid Certificate!",
            DenyReason::RoleActionMismatch => "Action-role mismatch!",
        }
    }
}

// --- Honeypot ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Honeypot {
    pub id: &'static str,
    pub fake_address: &'static str,
    pub persona: &'static str,
}

// who is allowed what + TTL by role.
#[derive(Debug)]
pub struct Policy {
    rules: HashMap<(Role, Sensitivity, ActionKind), u64>,
    honeypot: Honeypot,
    max_failed_attempts: u32,
}

// hardcoded policy for tests, move to .toml in future
impl Policy {
    pub fn demo() -> Self {
        Self {
            rules: HashMap::from([
                ((Role::Employee, Sensitivity::Internal, ActionKind::Read), 300),
                ((Role::Admin, Sensitivity::Critical, ActionKind::Read), 120),  
                ((Role::Contractor, Sensitivity::Public, ActionKind::Read), 250),
                ((Role::ServiceAccount, Sensitivity::Critical, ActionKind::Read), 200),
            ]),
            honeypot: Honeypot { id: "hp-01", fake_address: "https://zta.admin-panel", persona: "Admin" },
            max_failed_attempts: 3,
        }
    }
}

// Main function
pub fn evaluate(request: &AccessRequest, policy: &Policy) -> Decision {
    // --- Check Certificate ---
    match &request.subject.cert {
        CertStatus::Revoked { .. } => return Decision::Redirect {
            honeypot: policy.honeypot.clone(),
            reason: DenyReason::InvalidCert,
        }, // if "return" is missing, there'll be mismatched types
        CertStatus::Expired { .. } => return Decision::Deny {
            reason: DenyReason::InvalidCert,
        },
        CertStatus::Unknown => return Decision::Deny { reason: DenyReason::InvalidCert },
        CertStatus::Valid { .. } => {/* identity ok, go to risk check */},
    }

    // --- Check Risks ---
    match request.context.risk_signal {   // conditional branch (guard match pattern)
        RiskSignal::RepeatedFailures { count } if count >= policy.max_failed_attempts => {
            return Decision::Redirect {
                honeypot: policy.honeypot.clone(),
                reason: DenyReason::SuspiciousActivity,
            };
        }
        // there were attempts, but they < max_failed_attempts
        RiskSignal::RepeatedFailures { .. } => {}
        RiskSignal::Normal => {}
    }

    // tuples from Policy rules (HashMap)
    let key = (
        request.subject.role.clone(),
        request.resource.sensitivity.clone(),
        request.context.action,
    );

    // --- Auth (get key from policy) ---
    match policy.rules.get(&key) {
        Some(&ttl) => Decision::Allow {
            ttl_secs: ttl,
            auth_level: AuthLevel::SingleFactor,
        },
        None => Decision::Deny { reason: DenyReason::RoleActionMismatch },
    }
}

// --- Tests ---
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {}
}
