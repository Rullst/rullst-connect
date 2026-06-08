use crate::user::ConnectUser;
use crate::client::HttpClientExt;
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
        let encoded_state = url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>();
        format!("{url}{separator}state={encoded_state}")
    }

    /// Returns the authorization URL with a PKCE `code_challenge` appended.
    /// Useful for providers that enforce PKCE (like Twitter/X v2).
    fn redirect_url_with_pkce(&self, code_challenge: &str) -> String {
        let url = self.redirect_url();
        let separator = if url.contains('?') { "&" } else { "?" };
        let encoded_challenge = url::form_urlencoded::byte_serialize(code_challenge.as_bytes()).collect::<String>();
        format!(
            "{}{}code_challenge={}&code_challenge_method=S256",
            url, separator, encoded_challenge
        )
    }

    /// Returns the authorization URL with a PKCE `code_challenge` and a `state` parameter appended.
    fn redirect_url_with_pkce_and_state(&self, code_challenge: &str, state: &str) -> String {
        let url = self.redirect_url();
        let separator = if url.contains('?') { "&" } else { "?" };
        let encoded_challenge = url::form_urlencoded::byte_serialize(code_challenge.as_bytes()).collect::<String>();
        let encoded_state = url::form_urlencoded::byte_serialize(state.as_bytes()).collect::<String>();
        format!(
            "{}{}code_challenge={}&code_challenge_method=S256&state={}",
            url, separator, encoded_challenge, encoded_state
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

/// The response containing token information from a standard OAuth2 exchange.
#[derive(Debug, Clone)]
pub struct Oauth2TokenResponse {
    pub access_token: String,
    pub refresh_token: Option<String>,
    pub expires_in: Option<u64>,
}

/// Helper to exchange an authorization code for access tokens using standard OAuth2.
pub async fn fetch_access_token(
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_url: &str,
) -> Result<Oauth2TokenResponse, crate::error::ConnectError> {
    let token_res = client
        .post(token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", redirect_url),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    if let Some(err) = token_res["error"].as_str() {
        let err_desc = token_res["error_description"].as_str().unwrap_or("");
        return Err(crate::error::ConnectError::Token(format!(
            "Provider returned error: {} - {}",
            err, err_desc
        )));
    }

    let access_token = token_res["access_token"]
        .as_str()
        .ok_or_else(|| {
            crate::error::ConnectError::Token("Failed to get access_token".to_owned())
        })?
        .to_owned();

    let refresh_token = token_res["refresh_token"].as_str().map(String::from);
    let expires_in = token_res["expires_in"]
        .as_u64()
        .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));

    Ok(Oauth2TokenResponse {
        access_token,
        refresh_token,
        expires_in,
    })
}

/// Helper to exchange a refresh token for new access tokens using standard OAuth2.
pub async fn fetch_refresh_token(
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<Oauth2TokenResponse, crate::error::ConnectError> {
    let token_res = client
        .post(token_url)
        .form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ])
        .send()
        .await?
        .error_for_status()?
        .json::<serde_json::Value>()
        .await?;

    if let Some(err) = token_res["error"].as_str() {
        let err_desc = token_res["error_description"].as_str().unwrap_or("");
        return Err(crate::error::ConnectError::Token(format!(
            "Provider returned error: {} - {}",
            err, err_desc
        )));
    }

    let access_token = token_res["access_token"].as_str().ok_or_else(|| {
        crate::error::ConnectError::Token(
            "Failed to get access_token during refresh".to_owned(),
        )
    })?
    .to_owned();

    let refresh_token = token_res["refresh_token"].as_str().map(String::from);
    let expires_in = token_res["expires_in"]
        .as_u64()
        .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));

    Ok(Oauth2TokenResponse {
        access_token,
        refresh_token,
        expires_in,
    })
}

/// Helper to exchange an authorization code and build the ConnectUser profile.
pub async fn exchange_and_get_user<P>(
    provider: &P,
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    auth_code: &str,
    redirect_url: &str,
) -> Result<ConnectUser, crate::error::ConnectError>
where
    P: Provider + ?Sized,
{
    let token = fetch_access_token(
        client,
        token_url,
        client_id,
        client_secret,
        auth_code,
        redirect_url,
    )
    .await?;

    let mut user = provider.get_user_from_token(&token.access_token).await?;
    user.refresh_token = token.refresh_token;
    user.expires_in = token.expires_in;
    Ok(user)
}

/// Helper to refresh an access token and fetch the updated ConnectUser profile.
pub async fn refresh_and_get_user<P>(
    provider: &P,
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    refresh_token: &str,
) -> Result<ConnectUser, crate::error::ConnectError>
where
    P: Provider + ?Sized,
{
    let token = fetch_refresh_token(
        client,
        token_url,
        client_id,
        client_secret,
        refresh_token,
    )
    .await?;

    let mut user = provider.get_user_from_token(&token.access_token).await?;
    user.refresh_token = token.refresh_token;
    user.expires_in = token.expires_in;
    Ok(user)
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

    #[tokio::test]
    async fn test_default_poll_device_token() {
        let provider = DummyProvider {
            base_url: "".to_string(),
        };
        let result = provider.poll_device_token("some_code").await;

        assert!(result.is_err());
        match result.unwrap_err() {
            ConnectError::Provider(msg) => {
                assert_eq!(msg, "Device Authorization is not supported by this provider");
            }
            _ => panic!("Expected ConnectError::Provider"),
        }
    }

    #[test]
    fn test_redirect_url_with_pkce_and_state_multiple_query_params() {
        let provider_multiple_query = DummyProvider {
            base_url: "https://example.com/auth?foo=bar&baz=qux".to_string(),
        };
        assert_eq!(
            provider_multiple_query.redirect_url_with_pkce_and_state("my_challenge", "my_state"),
            "https://example.com/auth?foo=bar&baz=qux&code_challenge=my_challenge&code_challenge_method=S256&state=my_state"
        );
    }

    #[test]
    fn test_build_oauth_params_variations() {
        // 1. Empty scopes
        let mut serializer = build_oauth_params("client", "redirect", &[], None, None);
        let query = serializer.finish();
        assert!(query.contains("client_id=client"));
        assert!(query.contains("redirect_uri=redirect"));
        assert!(!query.contains("scope"));

        // 2. Single scope
        let scopes_single = [String::from("read")];
        let mut serializer = build_oauth_params("client", "redirect", &scopes_single, None, None);
        let query = serializer.finish();
        assert!(query.contains("scope=read"));

        // 3. Multiple scopes
        let scopes_multiple = [String::from("read"), String::from("write")];
        let mut serializer = build_oauth_params("client", "redirect", &scopes_multiple, Some("state123"), Some("pkce_challenge"));
        let query = serializer.finish();
        assert!(query.contains("scope=read+write"));
        assert!(query.contains("state=state123"));
        assert!(query.contains("code_challenge=pkce_challenge"));
        assert!(query.contains("code_challenge_method=S256"));
    }
}
