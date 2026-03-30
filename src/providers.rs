use async_trait::async_trait;
use chrono::{DateTime, Duration, Utc};
use std::collections::HashMap;
use tracing::{debug, warn};

use crate::error::ZenvError;

/// A dynamically issued credential with a finite lease.
#[derive(Debug, Clone)]
pub struct Credential {
    pub env_var: String,
    pub value: String,
    pub extras: HashMap<String, String>,
    pub issued_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub lease_id: String,
    pub provider: String,
}

impl Credential {
    /// Returns all env vars: the primary one + extras.
    pub fn to_env_map(&self) -> HashMap<String, String> {
        let mut map = self.extras.clone();
        map.insert(self.env_var.clone(), self.value.clone());
        map
    }

    /// True when less than 600 seconds remain before expiry.
    pub fn needs_renewal(&self) -> bool {
        let remaining = self.expires_at.signed_duration_since(Utc::now());
        remaining < Duration::seconds(600)
    }
}

/// Trait for secret providers that issue short-lived credentials.
#[async_trait]
pub trait SecretProvider: Send + Sync {
    async fn issue(&self) -> Result<Credential, ZenvError>;
    async fn renew(&self, credential: &Credential) -> Result<Credential, ZenvError>;
    async fn revoke(&self, credential: &Credential) -> Result<(), ZenvError>;
    fn name(&self) -> &str;
}

/// AWS STS provider — issues temporary session credentials via AssumeRole.
pub struct AwsStsProvider {
    pub role_arn: String,
    pub region: String,
}

#[async_trait]
impl SecretProvider for AwsStsProvider {
    async fn issue(&self) -> Result<Credential, ZenvError> {
        let session_name = format!("zenv-{}", &uuid::Uuid::new_v4().to_string()[..8]);
        debug!(
            "AWS STS AssumeRole: role_arn={}, session={}",
            self.role_arn, session_name
        );

        // Real implementation would use:
        // let sts_client = aws_sdk_sts::Client::new(&aws_config::load_from_env().await);
        // let resp = sts_client.assume_role()
        //     .role_arn(&self.role_arn)
        //     .role_session_name(&session_name)
        //     .duration_seconds(3600)
        //     .send().await?;
        // let creds = resp.credentials().unwrap();

        let now = Utc::now();
        let mut extras = HashMap::new();
        extras.insert(
            "AWS_SECRET_ACCESS_KEY".to_string(),
            format!("stub-secret-key-{}", &session_name),
        );
        extras.insert(
            "AWS_SESSION_TOKEN".to_string(),
            format!("stub-session-token-{}", &session_name),
        );
        extras.insert("AWS_REGION".to_string(), self.region.clone());

        Ok(Credential {
            env_var: "AWS_ACCESS_KEY_ID".to_string(),
            value: format!("ASIA{}", &uuid::Uuid::new_v4().to_string()[..16]),
            extras,
            issued_at: now,
            expires_at: now + Duration::hours(1),
            lease_id: session_name,
            provider: self.name().to_string(),
        })
    }

    async fn renew(&self, _credential: &Credential) -> Result<Credential, ZenvError> {
        // STS credentials cannot be renewed — issue fresh ones
        self.issue().await
    }

    async fn revoke(&self, credential: &Credential) -> Result<(), ZenvError> {
        debug!(
            "AWS STS revoke is a no-op (credentials expire naturally): lease={}",
            credential.lease_id
        );
        Ok(())
    }

    fn name(&self) -> &str {
        "aws-sts"
    }
}

/// Stripe provider — issues restricted API keys.
pub struct StripeProvider {
    pub _api_key: String,
}

#[async_trait]
impl SecretProvider for StripeProvider {
    async fn issue(&self) -> Result<Credential, ZenvError> {
        debug!("Stripe: issuing restricted key");

        // Real implementation would:
        // POST https://api.stripe.com/v1/ephemeral_keys
        // or create a restricted key via the Stripe API:
        // POST https://api.stripe.com/v1/api_keys
        // with permissions: { card_payments: "read", ... }

        let now = Utc::now();
        Ok(Credential {
            env_var: "STRIPE_SECRET_KEY".to_string(),
            value: format!("rk_test_{}", &uuid::Uuid::new_v4().to_string()[..24]),
            extras: HashMap::new(),
            issued_at: now,
            expires_at: now + Duration::hours(24),
            lease_id: format!("stripe-lease-{}", &uuid::Uuid::new_v4().to_string()[..8]),
            provider: self.name().to_string(),
        })
    }

    async fn renew(&self, _credential: &Credential) -> Result<Credential, ZenvError> {
        self.issue().await
    }

    async fn revoke(&self, credential: &Credential) -> Result<(), ZenvError> {
        debug!("Stripe: revoking restricted key lease={}", credential.lease_id);
        // Real implementation would:
        // DELETE https://api.stripe.com/v1/api_keys/{key_id}
        Ok(())
    }

    fn name(&self) -> &str {
        "stripe"
    }
}

/// Registry of active dynamic credential leases.
/// Credentials live in memory only — never written to disk.
pub struct LeaseRegistry {
    leases: Vec<(Credential, Box<dyn SecretProvider>)>,
}

impl LeaseRegistry {
    pub fn new() -> Self {
        Self {
            leases: Vec::new(),
        }
    }

    pub fn add(&mut self, credential: Credential, provider: Box<dyn SecretProvider>) {
        self.leases.push((credential, provider));
    }

    /// Returns all env vars from non-expired credentials.
    pub fn active_env_map(&self) -> HashMap<String, String> {
        let now = Utc::now();
        let mut map = HashMap::new();
        for (cred, _) in &self.leases {
            if cred.expires_at > now {
                map.extend(cred.to_env_map());
            }
        }
        map
    }

    /// Best-effort revocation of all leases. Logs warnings on failure.
    pub async fn revoke_all(&mut self) {
        for (cred, provider) in self.leases.drain(..) {
            if let Err(e) = provider.revoke(&cred).await {
                warn!(
                    "failed to revoke lease {} from {}: {}",
                    cred.lease_id,
                    cred.provider,
                    e
                );
            }
        }
    }
}
