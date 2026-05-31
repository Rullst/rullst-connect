use crate::client::{HttpClient, HttpClientExt, ReqwestClient};
use crate::error::ConnectError;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;
use std::sync::Arc;

pub struct OidcProvider {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) redirect_url: String,
    pub(crate) http_client: Arc<dyn HttpClient>,
    pub(crate) scopes: Vec<String>,
    pub(crate) state: Option<String>,
    pub(crate) pkce_challenge: Option<String>,

    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub userinfo_endpoint: String,
    pub jwks: jsonwebtoken::jwk::JwkSet,
    pub issuer: String,
}

impl OidcProvider {
    /// Discovers the OIDC configuration from the issuer URL and creates a new provider.
    pub async fn discover(
        issuer_url: &str,
        client_id: String,
        client_secret: String,
        redirect_url: String,
    ) -> Result<Self, ConnectError> {
        let well_known_url = if issuer_url.ends_with('/') {
            format!("{}.well-known/openid-configuration", issuer_url)
        } else {
            format!("{}/.well-known/openid-configuration", issuer_url)
        };

        let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new());
        let res = client
            .get(&well_known_url)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let authorization_endpoint = res["authorization_endpoint"]
            .as_str()
            .ok_or_else(|| {
                ConnectError::Provider("Missing authorization_endpoint in OIDC config".to_string())
            })?
            .to_string();

        let token_endpoint = res["token_endpoint"]
            .as_str()
            .ok_or_else(|| {
                ConnectError::Provider("Missing token_endpoint in OIDC config".to_string())
            })?
            .to_string();

        let userinfo_endpoint = res["userinfo_endpoint"]
            .as_str()
            .ok_or_else(|| {
                ConnectError::Provider("Missing userinfo_endpoint in OIDC config".to_string())
            })?
            .to_string();

        let jwks_uri = res["jwks_uri"]
            .as_str()
            .ok_or_else(|| ConnectError::Provider("Missing jwks_uri in OIDC config".to_string()))?
            .to_string();

        let issuer = res["issuer"]
            .as_str()
            .ok_or_else(|| ConnectError::Provider("Missing issuer in OIDC config".to_string()))?
            .to_string();

        // Fetch the JWKS public keys immediately
        let jwks = client
            .get(&jwks_uri)
            .send()
            .await?
            .error_for_status()?
            .json::<jsonwebtoken::jwk::JwkSet>()
            .await?;

        Ok(Self {
            client_id,
            client_secret,
            redirect_url,
            http_client: client,
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
            state: None,
            pkce_challenge: None,
            authorization_endpoint,
            token_endpoint,
            userinfo_endpoint,
            jwks,
            issuer,
        })
    }

    pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
        self.scopes = scopes.iter().map(|s| s.to_string()).collect();
        self
    }

    pub fn with_state(mut self, state: &str) -> Self {
        self.state = Some(state.to_string());
        self
    }

    pub fn with_pkce(mut self, challenge: &str) -> Self {
        self.pkce_challenge = Some(challenge.to_string());
        self
    }

    pub fn with_http_client(mut self, client: Arc<dyn HttpClient>) -> Self {
        self.http_client = client;
        self
    }
}

#[async_trait]
impl Provider for OidcProvider {
    fn redirect_url(&self) -> String {
        let mut params = crate::provider::build_oauth_params(
            &self.client_id,
            &self.redirect_url,
            &self.scopes,
            self.state.as_deref(),
            self.pkce_challenge.as_deref(),
        );
        format!("{}?{}", self.authorization_endpoint, params.finish())
    }

    #[tracing::instrument(skip(self, auth_code))]
    async fn get_user(&self, auth_code: &str) -> Result<ConnectUser, ConnectError> {
        let token_res = self
            .http_client
            .post(self.token_url())
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.client_secret.as_str()),
                ("code", auth_code),
                ("grant_type", "authorization_code"),
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

        let mut user = if let Some(id_token) = token_res["id_token"].as_str() {
            // Cryptographic OIDC Signature Validation
            if let Ok(header) = jsonwebtoken::decode_header(id_token) {
                let kid = header.kid.unwrap_or_default();
                if let Some(jwk) = self.jwks.find(&kid) {
                    if let Ok(decoding_key) = jsonwebtoken::DecodingKey::from_jwk(jwk) {
                        let mut validation = jsonwebtoken::Validation::new(header.alg);
                        validation.set_audience(&[&self.client_id]);
                        validation.set_issuer(&[&self.issuer]);
                        validation.validate_exp = true;

                        if let Ok(token_data) =
                            jsonwebtoken::decode::<Value>(id_token, &decoding_key, &validation)
                        {
                            let payload = token_data.claims;
                            ConnectUser {
                                id: payload["sub"]
                                    .as_str()
                                    .map(String::from)
                                    .unwrap_or_default(),
                                name: payload["name"]
                                    .as_str()
                                    .map(String::from)
                                    .unwrap_or_default(),
                                email: payload["email"].as_str().map(|s: &str| s.to_string()),
                                avatar_url: payload["picture"]
                                    .as_str()
                                    .map(|s: &str| s.to_string()),
                                email_verified: payload["email_verified"].as_bool(),
                                raw_data: payload,
                                access_token: access_token.to_string(),
                                refresh_token: None,
                                expires_in: None,
                            }
                        } else {
                            self.get_user_from_token(access_token).await?
                        }
                    } else {
                        self.get_user_from_token(access_token).await?
                    }
                } else {
                    self.get_user_from_token(access_token).await?
                }
            } else {
                self.get_user_from_token(access_token).await?
            }
        } else {
            self.get_user_from_token(access_token).await?
        };

        user.refresh_token = token_res["refresh_token"].as_str().map(|s| s.to_string());
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));

        Ok(user)
    }

    #[tracing::instrument(skip(self, access_token))]
    async fn get_user_from_token(&self, access_token: &str) -> Result<ConnectUser, ConnectError> {
        let user_res = self
            .http_client
            .get(&self.userinfo_endpoint)
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
                .map(String::from)
                .unwrap_or_default(),
            email: user_res["email"].as_str().map(|s: &str| s.to_string()),
            avatar_url: user_res["picture"].as_str().map(|s: &str| s.to_string()),
            email_verified: user_res["email_verified"].as_bool(),
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        self.token_endpoint.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::{Arc, Mutex};

    struct MockOidcClient {
        config_body: Value,
        jwks_body: Value,
        captured_urls: Mutex<Vec<String>>,
    }

    #[async_trait]
    impl HttpClient for MockOidcClient {
        async fn execute(
            &self,
            req: crate::client::HttpRequest,
        ) -> Result<crate::client::HttpResponse, crate::error::ConnectError> {
            self.captured_urls.lock().unwrap().push(req.url.clone());
            if req.url.contains("openid-configuration") {
                Ok(crate::client::HttpResponse {
                    status: 200,
                    body: self.config_body.clone(),
                })
            } else if req.url.contains("jwks") {
                Ok(crate::client::HttpResponse {
                    status: 200,
                    body: self.jwks_body.clone(),
                })
            } else {
                Err(crate::error::ConnectError::Provider(
                    "Not found".to_string(),
                ))
            }
        }
    }

    #[tokio::test]
    async fn test_oidc_discover_success_with_slash() {
        let mock_client = Arc::new(MockOidcClient {
            config_body: json!({
                "authorization_endpoint": "https://auth.com/authorize",
                "token_endpoint": "https://auth.com/token",
                "userinfo_endpoint": "https://auth.com/userinfo",
                "jwks_uri": "https://auth.com/jwks",
                "issuer": "https://issuer.com"
            }),
            jwks_body: json!({
                "keys": []
            }),
            captured_urls: Mutex::new(vec![]),
        });

        // Test with trailing slash
        let _provider = OidcProvider::discover(
            "https://issuer.com/",
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://redirect.url".to_string(),
        )
        .await
        .unwrap()
        .with_http_client(mock_client.clone());

        let urls = mock_client.captured_urls.lock().unwrap();
        assert_eq!(
            urls[0],
            "https://issuer.com/.well-known/openid-configuration"
        );
        assert_eq!(urls[1], "https://auth.com/jwks");
    }

    #[tokio::test]
    async fn test_oidc_discover_success_no_slash() {
        let mock_client = Arc::new(MockOidcClient {
            config_body: json!({
                "authorization_endpoint": "https://auth.com/authorize",
                "token_endpoint": "https://auth.com/token",
                "userinfo_endpoint": "https://auth.com/userinfo",
                "jwks_uri": "https://auth.com/jwks",
                "issuer": "https://issuer.com"
            }),
            jwks_body: json!({
                "keys": []
            }),
            captured_urls: Mutex::new(vec![]),
        });

        // Test without trailing slash
        let _provider = OidcProvider::discover(
            "https://issuer.com",
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://redirect.url".to_string(),
        )
        .await
        .unwrap()
        .with_http_client(mock_client.clone());

        let urls = mock_client.captured_urls.lock().unwrap();
        assert_eq!(
            urls[0],
            "https://issuer.com/.well-known/openid-configuration"
        );
        assert_eq!(urls[1], "https://auth.com/jwks");
    }

    #[tokio::test]
    async fn test_oidc_discover_missing_token_endpoint() {
        let mock_client = Arc::new(MockOidcClient {
            config_body: json!({
                "authorization_endpoint": "https://auth.com/authorize",
                "userinfo_endpoint": "https://auth.com/userinfo",
                "jwks_uri": "https://auth.com/jwks",
                "issuer": "https://issuer.com"
            }),
            jwks_body: json!({
                "keys": []
            }),
            captured_urls: Mutex::new(vec![]),
        });

        let res = OidcProvider::discover(
            "https://issuer.com",
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://redirect.url".to_string(),
        )
        .await;

        assert!(res.is_err());
        match res.unwrap_err() {
            crate::error::ConnectError::Provider(msg) => {
                assert!(msg.contains("Missing token_endpoint"));
            }
            _ => panic!("Expected Provider error"),
        }
    }
}
