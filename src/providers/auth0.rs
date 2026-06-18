use crate::client::HttpClientExt;
use crate::error::ConnectError;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

static DEFAULT_CLIENT: ::std::sync::LazyLock<::std::sync::Arc<dyn crate::client::HttpClient>> =
    ::std::sync::LazyLock::new(|| ::std::sync::Arc::new(crate::client::ReqwestClient::new()));

pub struct Auth0Provider {
    client_id: String,
    client_secret: String,
    redirect_url: String,
    domain: String,
    http_client: ::std::sync::Arc<dyn crate::client::HttpClient>,
    scopes: Vec<String>,
    state: Option<String>,
    pkce_challenge: Option<String>,
}

impl Auth0Provider {
    /// Note: domain should be the tenant domain, e.g., "dev-xxxx.us.auth0.com"
    pub fn new(
        client_id: String,
        client_secret: String,
        redirect_url: String,
        domain: String,
    ) -> Self {
        Self {
            client_id,
            client_secret,
            redirect_url,
            domain,
            http_client: DEFAULT_CLIENT.clone(),
            scopes: vec![
                "openid".to_owned(),
                "profile".to_owned(),
                "email".to_owned(),
            ],
            state: None,
            pkce_challenge: None,
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

    #[cfg(feature = "retry")]
    pub fn with_retry(mut self, max_retries: u32) -> Self {
        self.http_client =
            ::std::sync::Arc::new(crate::client::ReqwestClient::new_with_retry(max_retries));
        self
    }
}

#[async_trait]
impl Provider for Auth0Provider {
    fn redirect_url(&self) -> String {
        let mut params = crate::provider::build_oauth_params(
            format!("https://{}/authorize", self.domain),
            &self.client_id,
            &self.redirect_url,
            &self.scopes,
            self.state.as_deref(),
            self.pkce_challenge.as_deref(),
        );
        params.append_pair("response_type", "code");
        params.finish()
    }

    async fn get_user(
        &self,
        params: crate::provider::ExchangeParams<'_>,
    ) -> Result<crate::user::ConnectUser, crate::error::ConnectError> {
        crate::provider::exchange_and_get_user(
            self,
            self.http_client.as_ref(),
            &self.token_url(),
            &self.client_id,
            &self.client_secret,
            &self.redirect_url,
            &params,
        )
        .await
    }

    async fn get_user_from_token(&self, access_token: &str) -> Result<ConnectUser, ConnectError> {
        let user_res = self
            .http_client
            .get(format!("https://{}/userinfo", self.domain))
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        Ok(ConnectUser {
            id: user_res["sub"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing user id".to_owned())
            })?,
            name: user_res["name"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            email: user_res["email"].as_str().map(String::from),
            avatar_url: user_res["picture"].as_str().map(String::from),
            email_verified: user_res["email_verified"].as_bool(),
            raw_data: user_res,
            access_token: access_token.to_owned(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        format!("https://{}/oauth/token", self.domain)
    }

    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<crate::user::ConnectUser, crate::error::ConnectError> {
        let token = crate::provider::fetch_refresh_token(
            self.http_client.as_ref(),
            &self.token_url(),
            &self.client_id,
            &self.client_secret,
            refresh_token,
        )
        .await?;

        let mut user = self.get_user_from_token(&token.access_token).await?;
        user.refresh_token = token.refresh_token;
        user.expires_in = token.expires_in;
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;

    #[test]
    fn test_redirect_url() {
        let provider = Auth0Provider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://redirect.url".to_string(),
            "test.auth0.com".to_string(),
        );

        let url = provider.redirect_url();
        assert!(url.starts_with("https://test.auth0.com/authorize?"));
        assert!(url.contains("client_id=client_id"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fredirect.url"));
    }

    #[test]
    fn test_redirect_url_invalid_domain() {
        let provider = Auth0Provider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://redirect.url".to_string(),
            "invalid domain".to_string(), // Space makes it invalid
        );

        let url = provider.redirect_url();
        // Should fall back gracefully and not panic
        assert!(url.starts_with("https://invalid domain/authorize?"));
    }
}
