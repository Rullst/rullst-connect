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
    pub(crate) jwks: jsonwebtoken::jwk::JwkSet,
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
        let client: Arc<dyn HttpClient> = Arc::new(ReqwestClient::new());
        Self::discover_with_client(issuer_url, client_id, client_secret, redirect_url, client).await
    }

    /// Internal method that performs OIDC discovery using a provided HTTP client.
    /// This exists to enable injecting mock clients in tests.
    pub(crate) async fn discover_with_client(
        issuer_url: &str,
        client_id: String,
        client_secret: String,
        redirect_url: String,
        client: Arc<dyn HttpClient>,
    ) -> Result<Self, ConnectError> {
        let well_known_url = if issuer_url.ends_with('/') {
            format!("{}.well-known/openid-configuration", issuer_url)
        } else {
            format!("{}/.well-known/openid-configuration", issuer_url)
        };

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
                crate::error::ConnectError::Provider(
                    "Missing authorization_endpoint in OIDC config".to_string(),
                )
            })?
            .to_string();

        let token_endpoint = res["token_endpoint"]
            .as_str()
            .ok_or_else(|| {
                crate::error::ConnectError::Provider(
                    "Missing token_endpoint in OIDC config".to_string(),
                )
            })?
            .to_string();

        let userinfo_endpoint = res["userinfo_endpoint"]
            .as_str()
            .ok_or_else(|| {
                crate::error::ConnectError::Provider(
                    "Missing userinfo_endpoint in OIDC config".to_string(),
                )
            })?
            .to_string();

        let jwks_uri = res["jwks_uri"]
            .as_str()
            .ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing jwks_uri in OIDC config".to_string())
            })?
            .to_string();

        let issuer = res["issuer"]
            .as_str()
            .ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing issuer in OIDC config".to_string())
            })?
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

    pub fn with_http_client(mut self, client: Arc<dyn HttpClient>) -> Self {
        self.http_client = client;
        self
    }

    #[tracing::instrument(skip(self, form_data))]
    async fn get_user_from_form(
        &self,
        form_data: Vec<(&str, &str)>,
        expected_nonce: Option<&str>,
    ) -> Result<ConnectUser, ConnectError> {
        let token_res = self
            .http_client
            .post(self.token_url())
            .form(form_data)
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
            let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
                crate::error::ConnectError::Provider(format!(
                    "Failed to decode OIDC id_token header: {}",
                    e
                ))
            })?;

            if let Some(kid) = header.kid.as_ref() {
                let jwk = self.jwks.find(kid).ok_or_else(|| {
                    crate::error::ConnectError::Provider(format!(
                        "OIDC JWK with key ID '{}' not found",
                        kid
                    ))
                })?;
                let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|e| {
                    crate::error::ConnectError::Provider(format!(
                        "Failed to build OIDC decoding key from JWK: {}",
                        e
                    ))
                })?;
                let mut validation = jsonwebtoken::Validation::new(header.alg);
                validation.set_audience(&[&self.client_id]);
                validation.set_issuer(&[&self.issuer]);
                validation.validate_exp = true;
                if expected_nonce.is_some() {
                    validation.set_required_spec_claims(&["nonce"]);
                }

                let token_data =
                    jsonwebtoken::decode::<Value>(id_token, &decoding_key, &validation).map_err(
                        |e| {
                            crate::error::ConnectError::Provider(format!(
                                "OIDC id_token signature or claims validation failed: {}",
                                e
                            ))
                        },
                    )?;
                let payload = token_data.claims;

                if let Some(nonce) = expected_nonce
                    && payload["nonce"].as_str() != Some(nonce)
                {
                    return Err(crate::error::ConnectError::Provider(
                        "OIDC id_token nonce mismatch".to_owned(),
                    ));
                }

                ConnectUser {
                    id: payload["sub"].as_str().map(String::from).ok_or_else(|| {
                        crate::error::ConnectError::Provider("Missing sub in id_token".to_owned())
                    })?,
                    name: payload["name"].as_str().map(String::from).ok_or_else(|| {
                        crate::error::ConnectError::Provider("Missing name in id_token".to_owned())
                    })?,
                    email: payload["email"].as_str().map(String::from),
                    avatar_url: payload["picture"].as_str().map(String::from),
                    email_verified: payload["email_verified"].as_bool(),
                    raw_data: payload,
                    access_token: access_token.to_owned(),
                    refresh_token: None,
                    expires_in: None,
                }
            } else {
                return Err(crate::error::ConnectError::Provider(
                    "Missing 'kid' header in OIDC id_token".to_owned(),
                ));
            }
        } else {
            use crate::provider::Provider;
            self.get_user_from_token(access_token).await?
        };

        user.refresh_token = token_res["refresh_token"].as_str().map(String::from);
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));

        Ok(user)
    }
}

#[async_trait]
impl Provider for OidcProvider {
    crate::impl_standard_redirect_url!("{}");

    #[tracing::instrument(skip(self, params))]
    async fn get_user(
        &self,
        params: crate::provider::ExchangeParams<'_>,
    ) -> Result<ConnectUser, ConnectError> {
        let mut form_data = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", params.auth_code),
            ("grant_type", "authorization_code"),
            ("redirect_uri", self.redirect_url.as_str()),
        ];
        if let Some(verifier) = params.code_verifier {
            form_data.push(("code_verifier", verifier));
        }
        self.get_user_from_form(form_data, params.expected_nonce)
            .await
    }

    #[tracing::instrument(skip(self, access_token))]
    async fn get_user_from_token(&self, access_token: &str) -> Result<ConnectUser, ConnectError> {
        let user_res = self
            .http_client
            .get(&self.userinfo_endpoint)
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        Ok(ConnectUser {
            id: user_res["sub"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing sub in userinfo".to_owned())
            })?,
            name: user_res["name"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing name in userinfo".to_owned())
            })?,
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
        self.token_endpoint.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::sync::Arc;

    struct MockOidcClient {
        config_body: Value,
        jwks_body: Value,
        captured_urls: tokio::sync::Mutex<Vec<String>>,
    }

    #[async_trait]
    impl HttpClient for MockOidcClient {
        async fn execute(
            &self,
            req: crate::client::HttpRequest,
        ) -> Result<crate::client::HttpResponse, crate::error::ConnectError> {
            self.captured_urls.lock().await.push(req.url.clone());
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
            captured_urls: tokio::sync::Mutex::new(vec![]),
        });

        // Test with trailing slash
        let _provider = OidcProvider::discover_with_client(
            "https://issuer.com/",
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://redirect.url".to_string(),
            mock_client.clone(),
        )
        .await
        .expect("OIDC discovery failed");

        let urls = mock_client.captured_urls.lock().await;
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
            captured_urls: tokio::sync::Mutex::new(vec![]),
        });

        // Test without trailing slash
        let _provider = OidcProvider::discover_with_client(
            "https://issuer.com",
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://redirect.url".to_string(),
            mock_client.clone(),
        )
        .await
        .expect("OIDC discovery failed");

        let urls = mock_client.captured_urls.lock().await;
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
            captured_urls: tokio::sync::Mutex::new(vec![]),
        });

        let res = OidcProvider::discover_with_client(
            "https://issuer.com",
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://redirect.url".to_string(),
            mock_client.clone(),
        )
        .await;

        match res {
            Err(crate::error::ConnectError::Provider(msg)) => {
                assert!(msg.contains("Missing token_endpoint"));
            }
            Err(_) => panic!("Expected Provider error variant"),
            Ok(_) => panic!("Expected an error, but discover succeeded"),
        }
    }
}
