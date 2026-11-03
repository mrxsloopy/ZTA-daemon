//--- PDP-core ---
//use std::net::IpAddr;

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
#[derive(Debug, Clone, PartialEq, Eq)]
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

pub enum RiskSignal {
    Normal,
    RepeatedFailures { count: u32 }
}

// --- Sensitivity to a specific resource ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Sensitivity {
    Public,
    Internal,
    Critical,
}

// --- Subjects actions ---
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

// --- Honeypod ---
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Honeypot {
    pub id: String,
    pub fake_address: String,
    pub person: String,
}

/* --- SOC team monitoring
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SocAlertLevel {
    Monitor,
    CriticalTrap,
}*/

// who is allowed what + TTL by role.
pub struct Policy {
    // i think hashmap
}


impl Policy {
    /// hardcoded policy for tests, move to .toml in future
    pub fn demo() -> Self {
        // ...
    }
}

// Main function
pub fn evaluate(request: &AccessRequest, policy: &Policy) -> Decision {
}
