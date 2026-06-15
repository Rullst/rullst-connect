use crate::client::HttpClientExt;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::OnceCell;

static DEFAULT_CLIENT: ::std::sync::LazyLock<::std::sync::Arc<dyn crate::client::HttpClient>> =
    ::std::sync::LazyLock::new(|| ::std::sync::Arc::new(crate::client::ReqwestClient::new()));

pub struct AppleProvider {
    client_id: String,
    team_id: String,
    key_id: String,
    private_key_pem: String,
    redirect_url: String,
    http_client: ::std::sync::Arc<dyn crate::client::HttpClient>,
    scopes: Vec<String>,
    state: Option<String>,
    pkce_challenge: Option<String>,
    jwks: OnceCell<jsonwebtoken::jwk::JwkSet>,
}

#[derive(Debug, Serialize, Deserialize)]
struct AppleClaims<'a> {
    iss: &'a str,
    iat: u64,
    exp: u64,
    aud: &'a str,
    sub: &'a str,
}

impl AppleProvider {
    /// Apple requires a Team ID, a Key ID, and the contents of a .p8 Private Key file
    /// to dynamically generate the client_secret JWT on every login.
    pub fn new(
        client_id: String,
        team_id: String,
        key_id: String,
        private_key_pem: String,
        redirect_url: String,
    ) -> Self {
        Self {
            client_id,
            team_id,
            key_id,
            private_key_pem,
            redirect_url,
            http_client: DEFAULT_CLIENT.clone(),
            scopes: vec!["name".to_string(), "email".to_string()],
            state: None,
            pkce_challenge: None,
            jwks: OnceCell::new(),
        }
    }

    pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().copied().map(String::from).collect();
        self
    }

    pub fn with_state(mut self, state: &str) -> Self {
        self.state = Some(state.to_owned());
        self
    }

    pub fn with_pkce(mut self, challenge: &str) -> Self {
        self.pkce_challenge = Some(challenge.to_owned());
        self
    }

    pub fn with_http_client(
        mut self,
        client: ::std::sync::Arc<dyn crate::client::HttpClient>,
    ) -> Self {
        self.http_client = client;
        self
    }

    fn generate_client_secret(&self) -> Result<String, crate::error::ConnectError> {
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let claims = AppleClaims {
            iss: &self.team_id,
            iat: now,
            exp: now + 86400 * 30, // 30 days expiration
            aud: "https://appleid.apple.com",
            sub: &self.client_id,
        };

        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.key_id.clone());

        let encoding_key = EncodingKey::from_ec_pem(self.private_key_pem.as_bytes())?;
        let token = encode(&header, &claims, &encoding_key)?;

        Ok(token)
    }

    async fn get_jwks(&self) -> Result<&jsonwebtoken::jwk::JwkSet, crate::error::ConnectError> {
        self.jwks
            .get_or_try_init(|| async {
                let res = self
                    .http_client
                    .get("https://appleid.apple.com/auth/keys")
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<jsonwebtoken::jwk::JwkSet>()
                    .await?;
                Ok(res)
            })
            .await
    }
}

#[async_trait]
impl Provider for AppleProvider {
    async fn get_user_with_pkce(
        &self,
        auth_code: &str,
        _code_verifier: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        self.get_user(auth_code).await
    }

    fn redirect_url(&self) -> String {
        let mut params = crate::provider::build_oauth_params(
            &self.client_id,
            &self.redirect_url,
            &self.scopes,
            self.state.as_deref(),
            self.pkce_challenge.as_deref(),
        );
        params.append_pair("response_type", "code");
        params.append_pair("response_mode", "form_post");
        format!(
            "https://appleid.apple.com/auth/authorize?{}",
            params.finish()
        )
    }

    async fn get_user(&self, auth_code: &str) -> Result<ConnectUser, crate::error::ConnectError> {
        let client_secret = self.generate_client_secret()?;

        let token_res = self
            .http_client
            .post(self.token_url())
            .form([
                ("client_id", self.client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("code", auth_code),
                ("grant_type", "authorization_code"),
                ("redirect_uri", self.redirect_url.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        // Apple returns user data inside an "id_token" (JWT)
        let id_token_str = token_res["id_token"].as_str().ok_or_else(|| {
            crate::error::ConnectError::Token("Failed to get id_token from Apple".to_string())
        })?;
        let access_token = token_res["access_token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                crate::error::ConnectError::Token(
                    "Failed to get access_token from Apple".to_string(),
                )
            })?;

        let mut user = self.get_user_from_token(id_token_str).await?;
        user.access_token = access_token;
        user.refresh_token = token_res["refresh_token"].as_str().map(String::from);
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
    }

    /// For Apple, `access_token` parameter should actually be the `id_token` JWT string.
    async fn get_user_from_token(
        &self,
        id_token_str: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let mut payload: Option<Value> = None;

        if let Ok(header) = jsonwebtoken::decode_header(id_token_str)
            && let Some(kid) = header.kid.as_ref()
            && let Ok(jwks) = self.get_jwks().await
            && let Some(jwk) = jwks.find(kid)
            && let Ok(decoding_key) = jsonwebtoken::DecodingKey::from_jwk(jwk)
        {
            let mut validation = jsonwebtoken::Validation::new(header.alg);
            validation.set_audience(&[&self.client_id]);
            validation.set_issuer(&["https://appleid.apple.com"]);
            validation.validate_exp = true;

            if let Ok(token_data) =
                jsonwebtoken::decode::<Value>(id_token_str, &decoding_key, &validation)
            {
                payload = Some(token_data.claims);
            }
        }

        let payload = match payload {
            Some(p) => p,
            None => {
                return Err(crate::error::ConnectError::Provider(
                    "Failed to verify Apple id_token signature or claims".to_string(),
                ));
            }
        };

        Ok(ConnectUser {
            id: payload["sub"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing sub in Apple id_token".to_string())
            })?,
            name: String::with_capacity(256), // Developer needs to extract this from the form_post on first login
            email: payload["email"].as_str().map(String::from),
            avatar_url: None, // Apple does not provide avatars
            email_verified: None,
            raw_data: payload,
            access_token: id_token_str.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://appleid.apple.com/auth/token".to_string()
    }

    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let client_secret = self.generate_client_secret()?;

        let token_res = self
            .http_client
            .post(self.token_url())
            .form([
                ("client_id", self.client_id.as_str()),
                ("client_secret", client_secret.as_str()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<serde_json::Value>()
            .await?;

        if let Some(err) = token_res["error"].as_str() {
            let err_desc = token_res["error_description"].as_str().unwrap_or_default();
            return Err(crate::error::ConnectError::Token(format!(
                "Provider returned error: {} - {}",
                err, err_desc
            )));
        }

        let access_token = token_res["access_token"].as_str().ok_or_else(|| {
            crate::error::ConnectError::Token(
                "Failed to get access_token during refresh".to_string(),
            )
        })?;

        let mut user = self.get_user_from_token(access_token).await?;
        user.refresh_token = token_res["refresh_token"].as_str().map(String::from);
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_apple_redirect_url() {
        let provider = AppleProvider::new(
            "client_id".to_string(),
            "team_id".to_string(),
            "key_id".to_string(),
            "private_key".to_string(),
            "https://redirect.url".to_string(),
        );

        let url = provider.redirect_url();
        assert!(url.starts_with("https://appleid.apple.com/auth/authorize?"));
        assert!(url.contains("client_id=client_id"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fredirect.url"));
        assert!(url.contains("response_mode=form_post"));
    }

    #[tokio::test]
    async fn test_apple_get_user_from_token_invalid() {
        let provider = AppleProvider::new(
            "client_id".to_string(),
            "team_id".to_string(),
            "key_id".to_string(),
            "private_key".to_string(),
            "https://redirect.url".to_string(),
        );

        let res = provider.get_user_from_token("invalid.token.format").await;
        assert!(res.is_err());
        match res.unwrap_err() {
            crate::error::ConnectError::Provider(msg) => {
                assert!(msg.contains("Failed to verify Apple id_token"));
            }
            _ => panic!("Expected Provider error"),
        }
    }
}
