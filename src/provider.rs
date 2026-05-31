use crate::user::ConnectUser;
use async_trait::async_trait;

/// Helper to construct standard OAuth2 parameters to reduce boilerplate.
pub fn build_oauth_params<'a>(
    client_id: &'a str,
    redirect_uri: &'a str,
    scopes: &'a [String],
    state: Option<&'a str>,
    pkce_challenge: Option<&'a str>,
) -> url::form_urlencoded::Serializer<'a, String> {
    let mut params = url::form_urlencoded::Serializer::new(String::with_capacity(256));
    params.append_pair("client_id", client_id);
    params.append_pair("redirect_uri", redirect_uri);
    if !scopes.is_empty() {
        if scopes.len() == 1 {
            params.append_pair("scope", &scopes[0]);
        } else {
            params.append_pair("scope", &scopes.join(" "));
        }
    }
    if let Some(s) = state {
        params.append_pair("state", s);
    }
    if let Some(p) = pkce_challenge {
        params.append_pair("code_challenge", p);
        params.append_pair("code_challenge_method", "S256");
    }
    params
}

/// The core trait implemented by all OAuth2 providers in Rullst Connect.
#[async_trait]
pub trait Provider: Send + Sync {
    /// Returns the authorization URL to redirect the user to the provider's login screen.
    fn redirect_url(&self) -> String;

    /// Returns the authorization URL with a `state` parameter appended.
    /// It is highly recommended to use this to prevent CSRF attacks.
    fn redirect_url_with_state(&self, state: &str) -> String {
        let url = self.redirect_url();
        let separator = if url.contains('?') { "&" } else { "?" };
        format!("{url}{separator}state={state}")
    }

    /// Returns the authorization URL with a PKCE `code_challenge` appended.
    /// Useful for providers that enforce PKCE (like Twitter/X v2).
    fn redirect_url_with_pkce(&self, code_challenge: &str) -> String {
        let url = self.redirect_url();
        let separator = if url.contains('?') { "&" } else { "?" };
        format!(
            "{}{}code_challenge={}&code_challenge_method=S256",
            url, separator, code_challenge
        )
    }

    /// Returns the authorization URL with a PKCE `code_challenge` and a `state` parameter appended.
    fn redirect_url_with_pkce_and_state(&self, code_challenge: &str, state: &str) -> String {
        let url = self.redirect_url();
        let separator = if url.contains('?') { "&" } else { "?" };
        format!(
            "{}{}code_challenge={}&code_challenge_method=S256&state={}",
            url, separator, code_challenge, state
        )
    }

    /// Exchanges the authorization code for an access token and fetches the user's profile.
    /// Returns a standardized `ConnectUser` or a `ConnectError`.
    async fn get_user(&self, auth_code: &str) -> Result<ConnectUser, crate::error::ConnectError>;

    /// Exchanges the authorization code for an access token using a PKCE `code_verifier`.
    /// Fallbacks to standard `get_user` by default. Must be overridden by PKCE-enforcing providers.
    async fn get_user_with_pkce(
        &self,
        auth_code: &str,
        _code_verifier: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        self.get_user(auth_code).await
    }

    /// Fetches the user's profile using an existing access token.
    /// This bypasses the authorization code exchange step.
    async fn get_user_from_token(
        &self,
        access_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError>;

    /// Returns the URL used to exchange the authorization code for an access token.
    fn token_url(&self) -> String;

    /// Exchanges a refresh token for a new access token and fetches the user profile.
    async fn refresh_token(
        &self,
        _refresh_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        Err(crate::error::ConnectError::Token(
            "Refresh token is not supported by this provider".to_string(),
        ))
    }

    /// Revokes an access token (or refresh token) directly on the provider's authorization server.
    /// By default, this returns a `Token` error since not all providers support token revocation.
    async fn revoke_token(&self, _token: &str) -> Result<(), crate::error::ConnectError> {
        Err(crate::error::ConnectError::Token(
            "Token revocation is not supported by this provider".to_string(),
        ))
    }

    /// Initiates a device authorization flow (RFC 8628).
    /// Returns the device code, user code, and verification URI.
    async fn request_device_code(
        &self,
    ) -> Result<crate::user::DeviceAuthorizationResponse, crate::error::ConnectError> {
        Err(crate::error::ConnectError::Provider(
            "Device Authorization is not supported by this provider".into(),
        ))
    }

    /// Polls the provider for the access token during a device authorization flow.
    /// Returns the user's profile if the user has authorized the device.
    async fn poll_device_token(
        &self,
        _device_code: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        Err(crate::error::ConnectError::Provider(
            "Device Authorization is not supported by this provider".into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::ConnectError;
    use crate::user::ConnectUser;
    use async_trait::async_trait;

    struct DummyProvider {
        base_url: String,
    }

    #[async_trait]
    impl Provider for DummyProvider {
        fn redirect_url(&self) -> String {
            self.base_url.clone()
        }

        fn token_url(&self) -> String {
            "".to_string()
        }

        async fn get_user(&self, _auth_code: &str) -> Result<ConnectUser, ConnectError> {
            unimplemented!()
        }

        async fn get_user_from_token(
            &self,
            _access_token: &str,
        ) -> Result<ConnectUser, ConnectError> {
            unimplemented!()
        }
    }

    #[test]
    fn test_redirect_url_with_state() {
        let provider_no_query = DummyProvider {
            base_url: "https://example.com/auth".to_string(),
        };
        assert_eq!(
            provider_no_query.redirect_url_with_state("my_state"),
            "https://example.com/auth?state=my_state"
        );

        let provider_with_query = DummyProvider {
            base_url: "https://example.com/auth?client_id=123".to_string(),
        };
        assert_eq!(
            provider_with_query.redirect_url_with_state("my_state"),
            "https://example.com/auth?client_id=123&state=my_state"
        );
    }

    #[test]
    fn test_redirect_url_with_pkce() {
        let provider_no_query = DummyProvider {
            base_url: "https://example.com/auth".to_string(),
        };
        assert_eq!(
            provider_no_query.redirect_url_with_pkce("my_challenge"),
            "https://example.com/auth?code_challenge=my_challenge&code_challenge_method=S256"
        );

        let provider_with_query = DummyProvider {
            base_url: "https://example.com/auth?client_id=123".to_string(),
        };
        assert_eq!(
            provider_with_query.redirect_url_with_pkce("my_challenge"),
            "https://example.com/auth?client_id=123&code_challenge=my_challenge&code_challenge_method=S256"
        );
    }

    #[test]
    fn test_redirect_url_with_pkce_and_state() {
        let provider_no_query = DummyProvider {
            base_url: "https://example.com/auth".to_string(),
        };
        assert_eq!(
            provider_no_query.redirect_url_with_pkce_and_state("my_challenge", "my_state"),
            "https://example.com/auth?code_challenge=my_challenge&code_challenge_method=S256&state=my_state"
        );

        let provider_with_query = DummyProvider {
            base_url: "https://example.com/auth?client_id=123".to_string(),
        };
        assert_eq!(
            provider_with_query.redirect_url_with_pkce_and_state("my_challenge", "my_state"),
            "https://example.com/auth?client_id=123&code_challenge=my_challenge&code_challenge_method=S256&state=my_state"
        );
    }

    #[tokio::test]
    async fn test_default_revoke_token() {
        let provider = DummyProvider {
            base_url: "".to_string(),
        };
        let result = provider.revoke_token("some_token").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ConnectError::Token(msg) => {
                assert_eq!(msg, "Token revocation is not supported by this provider");
            }
            _ => panic!("Expected ConnectError::Token"),
        }
    }
}
