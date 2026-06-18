use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Represents a standardized user profile returned from any OAuth2 provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectUser {
    /// The unique identifier of the user in the provider's system.
    pub id: String,

    /// The full name or display name of the user.
    pub name: String,

    /// The email address of the user, if available and granted.
    pub email: Option<String>,

    /// Indicates whether the provider has verified the user's email address.
    pub email_verified: Option<bool>,

    /// The URL to the user's avatar/profile picture, if available.
    pub avatar_url: Option<String>,

    /// The raw JSON response received from the provider's user endpoint.
    /// Useful for extracting provider-specific fields not covered by this struct.
    pub raw_data: Value,

    /// The access token retrieved during the OAuth2 flow.
    pub access_token: String,

    /// The refresh token retrieved during the OAuth2 flow (if provided).
    pub refresh_token: Option<String>,

    /// The token expiration time in seconds from the time it was granted (if provided).
    pub expires_in: Option<u64>,
}

use async_trait::async_trait;

/// Helper trait to seamlessly integrate `ConnectUser` with databases and ORMs (like SQLx, Diesel, rullst-orm).
/// By implementing this trait on your custom database User model or repository, you can easily
/// save or update users directly from the OAuth profile.
#[async_trait]
pub trait IntoDatabaseUser<T> {
    /// Inserts or updates the user in the database based on the OAuth profile.
    /// Returns the database-specific User model or an error.
    async fn sync_from_oauth(profile: &ConnectUser) -> Result<T, crate::error::ConnectError>;
}

/// Represents the response from a device authorization request (RFC 8628).
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct DeviceAuthorizationResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_connect_user_serialization() {
        let user = ConnectUser {
            id: "123".to_string(),
            name: "Test User".to_string(),
            email: Some("test@example.com".to_string()),
            email_verified: Some(true),
            avatar_url: Some("https://example.com/avatar.png".to_string()),
            raw_data: json!({"custom_field": "custom_value"}),
            access_token: "access123".to_string(),
            refresh_token: Some("refresh123".to_string()),
            expires_in: Some(3600),
        };

        let serialized = serde_json::to_string(&user).unwrap();
        let deserialized: ConnectUser = serde_json::from_str(&serialized).unwrap();

        assert_eq!(user.id, deserialized.id);
        assert_eq!(user.name, deserialized.name);
        assert_eq!(user.email, deserialized.email);
        assert_eq!(user.email_verified, deserialized.email_verified);
        assert_eq!(user.avatar_url, deserialized.avatar_url);
        assert_eq!(user.raw_data, deserialized.raw_data);
        assert_eq!(user.access_token, deserialized.access_token);
        assert_eq!(user.refresh_token, deserialized.refresh_token);
        assert_eq!(user.expires_in, deserialized.expires_in);
    }
}
