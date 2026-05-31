use crate::error::ConnectError;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use reqwest::Client;
use serde_json::Value;

pub struct CognitoProvider {
    client_id: String,
    client_secret: String,
    redirect_url: String,
    domain: String,
    http_client: Client,
    scopes: Vec<String>,
    state: Option<String>,
    pkce_challenge: Option<String>,
}

impl CognitoProvider {
    /// Note: domain should be the full base url, e.g., <https://my-domain.auth.us-east-1.amazoncognito.com>
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_url: String,
        domain: String,
    ) -> Self {
        let clean_domain = domain.trim_end_matches('/').to_string();
        Self {
            client_id,
            client_secret,
            redirect_url,
            domain: clean_domain,
            http_client: Client::new(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            state: None,
            pkce_challenge: None,
        }
    }

    /// Overrides the default scopes for this provider.
    pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s: &&str| s.to_string()).collect();
        self
    }

    /// Sets the state parameter for CSRF protection.
    pub fn with_state(mut self, state: &str) -> Self {
        self.state = Some(state.to_string());
        self
    }

    pub fn with_pkce(mut self, challenge: &str) -> Self {
        self.pkce_challenge = Some(challenge.to_string());
        self
    }
}

#[async_trait]
impl Provider for CognitoProvider {
    fn redirect_url(&self) -> String {
        let mut params = crate::provider::build_oauth_params(
            &self.client_id,
            &self.redirect_url,
            &self.scopes,
            self.state.as_deref(),
            self.pkce_challenge.as_deref(),
        );
        format!("{}/oauth2/authorize?{}", self.domain, params.finish())
    }

    async fn get_user(&self, auth_code: &str) -> Result<ConnectUser, ConnectError> {
        let token_res = self
            .http_client
            .post(self.token_url())
            .form(&[
                ("grant_type", "authorization_code"),
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", auth_code),
                ("redirect_uri", self.redirect_url.as_str()),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let access_token = token_res["access_token"]
            .as_str()
            .ok_or_else(|| ConnectError::Token("Failed to get access_token".to_string()))?;

        let mut user = self.get_user_from_token(access_token).await?;
        user.refresh_token = token_res["refresh_token"]
            .as_str()
            .map(|s: &str| s.to_string());
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
    }

    async fn get_user_from_token(&self, access_token: &str) -> Result<ConnectUser, ConnectError> {
        let user_res = self
            .http_client
            .get(format!("{}/oauth2/userInfo", self.domain))
            .header("Authorization", format!("Bearer {}", access_token))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        Ok(ConnectUser {
            id: user_res["sub"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            name: user_res["name"]
                .as_str()
                .or_else(|| user_res["username"].as_str())
                .unwrap_or("")
                .to_string(),
            email: user_res["email"].as_str().map(|s: &str| s.to_string()),
            avatar_url: user_res["picture"].as_str().map(|s: &str| s.to_string()),
            email_verified: None,
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        format!("{}/oauth2/token", self.domain)
    }

    async fn refresh_token(&self, refresh_token: &str) -> Result<ConnectUser, ConnectError> {
        let token_res = self
            .http_client
            .post(self.token_url())
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("refresh_token", refresh_token),
                ("grant_type", "refresh_token"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        if let Some(err) = token_res["error"].as_str() {
            let err_desc = token_res["error_description"].as_str().unwrap_or("");
            return Err(ConnectError::Token(format!(
                "Provider returned error: {} - {}",
                err, err_desc
            )));
        }

        let access_token = token_res["access_token"].as_str().ok_or_else(|| {
            ConnectError::Token("Failed to get access_token during refresh".to_string())
        })?;

        let mut user = self.get_user_from_token(access_token).await?;
        user.refresh_token = token_res["refresh_token"]
            .as_str()
            .map(|s: &str| s.to_string());
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
    }
}
