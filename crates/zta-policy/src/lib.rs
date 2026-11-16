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
    #[must_use]
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
    #[must_use]
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
#[must_use]
pub fn evaluate(request: &AccessRequest, policy: &Policy) -> Decision {
    // --- Check Certificate ---
    match &request.subject.cert {
        CertStatus::Revoked { .. } => return Decision::Redirect {
            honeypot: policy.honeypot.clone(),
            reason: DenyReason::InvalidCert,
        }, // if "return" is missing, there'll be mismatched types
        CertStatus::Expired { .. } | CertStatus::Unknown => return Decision::Deny {
            reason: DenyReason::InvalidCert,
        },
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
        RiskSignal::RepeatedFailures { .. } | RiskSignal::Normal => {}
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

    // --- Builders ---
    // Policy with rules
    fn policy() -> Policy { Policy::demo() }
    // Default request
    fn make_request(  // parameter declaration
        role: Role,
        sensitivity: Sensitivity,
        action: ActionKind,
        risk: RiskSignal,
    ) -> AccessRequest {
        AccessRequest {
            subject: Subject {
                id: "0x".to_string(),
                role,
                cert: CertStatus::Valid {
                    expires_in_secs: 300,
                    fingerprint: "aa:bb:cc:...".to_string(),
                    trusted_ca: "ZTA Demo Root CA".to_string(),
                }
            }, 
            resource: Resource { name: "res".to_string(), sensitivity },
            context: RequestContext { action, request_id: "req-01".to_string(), risk_signal: risk },
        }
    }
    // Copy of make request, but cert - parametr
    fn request_with_cert(cert: CertStatus) -> AccessRequest {
        AccessRequest {
            subject: Subject { id: "0x".to_string(), role: Role::Employee, cert },
            resource: Resource { name: "res".to_string(), sensitivity: Sensitivity::Internal },
            context: RequestContext {
                action: ActionKind::Read,
                request_id: "req-01".to_string(),
                risk_signal: RiskSignal::Normal,
            },
        }
    }
    // Custom checker, for certs
    fn assert_cert_decision(cert: CertStatus, expected: &Decision) {
        let req = request_with_cert(cert);
        assert_eq!(evaluate(&req, &policy()), expected.clone());
    }

    /* --------------------------------------------- */
    
    #[test]
    fn allow_employee_reading_internal_resource() {
        let req = make_request(
            Role::Employee,
            Sensitivity::Internal,
            ActionKind::Read,
            RiskSignal::Normal,
        );
        assert_eq!(
            evaluate(&req, &policy()), 
            Decision::Allow { ttl_secs: 300, auth_level: AuthLevel::SingleFactor }
        );
    }

    #[test]
    fn deny_employee_reading_critical_resource() {
        let req = make_request(
            Role::Employee,
            Sensitivity::Critical,
            ActionKind::Read,
            RiskSignal::Normal
        );
        assert_eq!(
            evaluate(&req, &policy()),
            Decision::Deny { reason: DenyReason::RoleActionMismatch }  
        );
    }

    #[test]
    fn redirect_revoked_cert() {
        assert_cert_decision(
            CertStatus::Revoked { revoked_at: 1_000_000_000, reason: "key compromised".to_string() },
            &Decision::Redirect { honeypot: policy().honeypot.clone(), reason: DenyReason::InvalidCert },
        );
    }

    #[test]
    fn allow_admin_reading_critical_resource() {
        let req = make_request(
            Role::Admin,
            Sensitivity::Critical,
            ActionKind::Read,
            RiskSignal::Normal,
        );
        assert_eq!(
            evaluate(&req, &policy()),
            Decision::Allow { ttl_secs: 120, auth_level: AuthLevel::SingleFactor }
        );
    }

    #[test]
    fn redirect_contractor_if_many_login_attempts() {
        let req = make_request(
            Role::Contractor,
            Sensitivity::Critical,
            ActionKind::Read,
            RiskSignal::RepeatedFailures { count: 4 }
        );
        assert_eq!(
            evaluate(&req, &policy()),
            Decision::Redirect { honeypot: policy().honeypot.clone(), reason: DenyReason::SuspiciousActivity }
        );
    }

    #[test]
    fn deny_contractor_reading_critical_resource() {
        let req = make_request(
            Role::Contractor,
            Sensitivity::Critical,
            ActionKind::Read,
            RiskSignal::Normal,
        );
        assert_eq!(
            evaluate(&req, &policy()),
            Decision::Deny { reason: DenyReason::RoleActionMismatch }
        );
    }

    #[test]
    fn allow_contractor_reading_public_resource() {
        let req = make_request(
            Role::Contractor,
            Sensitivity::Public,
            ActionKind::Read,
            RiskSignal::Normal,
        );
        assert_eq!(
            evaluate(&req, &policy()),
            Decision::Allow { ttl_secs: 250, auth_level: AuthLevel::SingleFactor }
        );
    }

    #[test]
    fn deny_expired_certificate() {
        assert_cert_decision(
            CertStatus::Expired { expired_at: 1_000_000_000, reason: "expired cert".to_string() },
            &Decision::Deny { reason: DenyReason::InvalidCert }
        );
    }

    #[test]
    fn deny_unknown_certificate() {
        assert_cert_decision(
            CertStatus::Unknown,
            &Decision::Deny { reason: DenyReason::InvalidCert }
        );
    }

    #[test]
    fn allow_serviceaccount_read_critical_resource() {
        let req = make_request(
            Role::ServiceAccount,
            Sensitivity::Critical,
            ActionKind::Read,
            RiskSignal::Normal,
        );
        assert_eq!(
            evaluate(&req, &policy()),
            Decision::Allow { ttl_secs: 200, auth_level: AuthLevel::SingleFactor }
        );
    }

    #[test]
    fn allow_contractor_if_not_many_login_attempts() {
        let req = make_request(
            Role::Contractor,
            Sensitivity::Public,
            ActionKind::Read,
            RiskSignal::RepeatedFailures { count: 2 },
        );
        assert_eq!(
            evaluate(&req, &policy()),
            Decision::Allow { ttl_secs: 250, auth_level: AuthLevel::SingleFactor }
        );
    }

    #[test]
    fn redirect_revoked_cert_before_risk_check() {
        let req = make_request(    // the same factory, but cert default (valid)
            Role::Contractor,
            Sensitivity::Critical,
            ActionKind::Read,
            RiskSignal::RepeatedFailures { count: 5 },
        );
        // manual substituation (sample)
        let req = AccessRequest {
            subject: Subject { cert: CertStatus::Revoked { revoked_at: 1_000_000_000, reason: "key compromised".to_string() }, ..req.subject },
            ..req
        };
        assert_eq!(
            evaluate(&req, &policy()),
            Decision::Redirect { honeypot: policy().honeypot.clone(), reason: DenyReason::InvalidCert }
        );
    }
}
