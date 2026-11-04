//--- PDP-core ---
#![warn(clippy::pedantic)]
use std::collections::HashMap;

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
        expires_in_secs: u64,
        fingerprint: String,
        trusted_ca: String,
        //allowed_scope: Vec<String>, realized in evaulate
    },
    Expired { expired_at: u64, reason: String },
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
    pub id: String,
    pub fake_address: String,
    pub person: String,
}

// who is allowed what + TTL by role.
#[derive(Debug)]
pub struct Policy {
    rules: HashMap<(Role, Sensitivity, ActionKind), u64>,
}

// hardcoded policy for tests, move to .toml in future
impl Policy {
    pub fn demo() -> Self {
        Self {
            rules: HashMap::from([
                ((Role::Employee, Sensitivity::Internal, ActionKind::Read), 500),
                ((Role::Admin, Sensitivity::Critical, ActionKind::Read), 500),  
                ((Role::Contractor, Sensitivity::Critical, ActionKind::Read), 250),
                ((Role::ServiceAccount, Sensitivity::Critical, ActionKind::Read), 300),
            ]),
        }
    }
}

// Main function
pub fn evaluate(request: &AccessRequest, policy: &Policy) -> Decision {
}
