use crate::client::HttpClientExt;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;
use tokio::sync::OnceCell;

static DEFAULT_CLIENT: ::std::sync::LazyLock<::std::sync::Arc<dyn crate::client::HttpClient>> =
    ::std::sync::LazyLock::new(|| ::std::sync::Arc::new(crate::client::ReqwestClient::new()));

pub struct GoogleProvider {
    pub(crate) client_id: String,
    pub(crate) client_secret: String,
    pub(crate) redirect_url: String,
    pub(crate) http_client: ::std::sync::Arc<dyn crate::client::HttpClient>,
    pub(crate) scopes: Vec<String>,
    pub(crate) state: Option<String>,
    pub(crate) pkce_challenge: Option<String>,
    pub(crate) jwks: OnceCell<jsonwebtoken::jwk::JwkSet>,
}

#[derive(serde::Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    id_token: Option<String>,
    refresh_token: Option<String>,
    expires_in: Option<u64>,
}

impl GoogleProvider {
    pub fn new(client_id: String, client_secret: String, redirect_url: String) -> Self {
        debug_assert!(
            !client_id.is_empty(),
            "Socialite Error: client_id cannot be empty"
        );
        debug_assert!(
            !client_secret.is_empty(),
            "Socialite Error: client_secret cannot be empty"
        );
        debug_assert!(
            redirect_url.starts_with("http"),
            "Socialite Error: redirect_url must be a valid HTTP/HTTPS URL"
        );

        Self {
            client_id,
            client_secret,
            redirect_url,
            http_client: DEFAULT_CLIENT.clone(),
            scopes: vec![
                "openid".to_string(),
                "profile".to_string(),
                "email".to_string(),
            ],
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

    #[cfg(feature = "retry")]
    pub fn with_retry(mut self, max_retries: u32) -> Self {
        self.http_client =
            ::std::sync::Arc::new(crate::client::ReqwestClient::new_with_retry(max_retries));
        self
    }

    async fn get_jwks(&self) -> Result<&jsonwebtoken::jwk::JwkSet, crate::error::ConnectError> {
        self.jwks
            .get_or_try_init(|| async {
                let res = self
                    .http_client
                    .get("https://www.googleapis.com/oauth2/v3/certs")
                    .send()
                    .await?
                    .error_for_status()?
                    .json::<jsonwebtoken::jwk::JwkSet>()
                    .await?;
                Ok(res)
            })
            .await
    }

    async fn get_user_from_form(
        &self,
        form_data: Vec<(&str, &str)>,
        expected_nonce: Option<&str>,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        // Exchange code for token
        let token_res = self
            .http_client
            .post("https://oauth2.googleapis.com/token")
            .form(form_data)
            .send()
            .await?
            .error_for_status()?
            .json::<GoogleTokenResponse>()
            .await?;

        let access_token = token_res.access_token;

        let mut user = if let Some(id_token) = &token_res.id_token {
            // Secure OIDC: Verify the signature of Google's id_token
            let header = jsonwebtoken::decode_header(id_token).map_err(|e| {
                crate::error::ConnectError::Provider(format!(
                    "Failed to decode Google id_token header: {}",
                    e
                ))
            })?;

            if let Some(kid) = header.kid.as_ref() {
                let jwks = self.get_jwks().await?;
                let jwk = jwks.find(kid).ok_or_else(|| {
                    crate::error::ConnectError::Provider(format!(
                        "Google JWK with key ID '{}' not found",
                        kid
                    ))
                })?;
                let decoding_key = jsonwebtoken::DecodingKey::from_jwk(jwk).map_err(|e| {
                    crate::error::ConnectError::Provider(format!(
                        "Failed to build Google decoding key: {}",
                        e
                    ))
                })?;

                let mut validation = jsonwebtoken::Validation::new(header.alg);
                validation.set_audience(&[&self.client_id]);
                validation.set_issuer(&["https://accounts.google.com", "accounts.google.com"]);
                validation.validate_exp = true;
                if expected_nonce.is_some() {
                    validation.set_required_spec_claims(&["nonce"]);
                }

                let token_data =
                    jsonwebtoken::decode::<Value>(id_token, &decoding_key, &validation).map_err(
                        |e| {
                            crate::error::ConnectError::Provider(format!(
                                "Google id_token validation failed: {}",
                                e
                            ))
                        },
                    )?;

                let p = token_data.claims;

                if let Some(nonce) = expected_nonce {
                    if p["nonce"].as_str() != Some(nonce) {
                        return Err(crate::error::ConnectError::Provider(
                            "Google id_token nonce mismatch".to_owned(),
                        ));
                    }
                }

                ConnectUser {
                    id: p["sub"].as_str().map(String::from).ok_or_else(|| {
                        crate::error::ConnectError::Provider(
                            "Missing sub claim in Google id_token".to_owned(),
                        )
                    })?,
                    name: p["name"].as_str().map(String::from).unwrap_or_default(),
                    email: p["email"].as_str().map(String::from),
                    avatar_url: p["picture"]
                        .as_str()
                        .map(|s: &str| s.replace("=s96-c", "=s400-c")),
                    email_verified: p["email_verified"].as_bool(),
                    raw_data: p,
                    access_token,
                    refresh_token: None,
                    expires_in: None,
                }
            } else {
                return Err(crate::error::ConnectError::Provider(
                    "Missing 'kid' header in Google id_token".to_owned(),
                ));
            }
        } else {
            self.get_user_from_token(&access_token).await?
        };

        user.refresh_token = token_res.refresh_token;
        user.expires_in = token_res.expires_in;
        Ok(user)
    }
}

#[async_trait]
impl Provider for GoogleProvider {
    crate::impl_standard_redirect_url!("https://accounts.google.com/o/oauth2/v2/auth");

    async fn get_user(
        &self,
        params: crate::provider::ExchangeParams<'_>,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
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

    async fn get_user_from_token(
        &self,
        access_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        // Fetch user profile
        let user_res = self
            .http_client
            .get("https://www.googleapis.com/oauth2/v3/userinfo")
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
            name: user_res["name"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            email: user_res["email"].as_str().map(String::from),
            avatar_url: user_res["picture"]
                .as_str()
                .map(|s: &str| s.replace("=s96-c", "=s400-c")),
            email_verified: user_res["email_verified"].as_bool(),
            raw_data: user_res,
            access_token: access_token.to_owned(),
            refresh_token: None,
            expires_in: None,
        })
    }

    async fn revoke_token(&self, token: &str) -> Result<(), crate::error::ConnectError> {
        self.http_client
            .post("https://oauth2.googleapis.com/revoke")
            .form([("token", token)])
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    fn token_url(&self) -> String {
        "https://oauth2.googleapis.com/token".to_string()
    }

    crate::impl_standard_refresh_token!();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::provider::Provider;

    #[test]
    fn test_google_redirect_url() {
        let provider = GoogleProvider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "https://redirect.url".to_string(),
        );

        let url = provider.redirect_url();
        assert!(url.starts_with("https://accounts.google.com/o/oauth2/v2/auth?"));
        assert!(url.contains("client_id=client_id"));
        assert!(url.contains("redirect_uri=https%3A%2F%2Fredirect.url"));
    }
}
