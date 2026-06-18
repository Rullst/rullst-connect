use crate::client::HttpClientExt;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(GithubProvider, "user:email");

impl GithubProvider {
    async fn get_user_from_form(
        &self,
        form_data: &crate::provider::TokenExchangeForm<'_>,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        // 1. Exchange authorization code for access token
        let token_res = self
            .http_client
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(form_data)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        if let Some(err) = token_res["error"].as_str() {
            let err_desc = token_res["error_description"].as_str().unwrap_or("");
            return Err(crate::error::ConnectError::Token(format!(
                "Provider returned error: {} - {}",
                err, err_desc
            )));
        }

        let access_token = token_res["access_token"].as_str().ok_or_else(|| {
            crate::error::ConnectError::Token("Failed to get access_token".to_string())
        })?;

        let mut user = self.get_user_from_token(access_token).await?;
        user.refresh_token = token_res["refresh_token"]
            .as_str()
            .map(|s| secrecy::SecretString::from(s.to_string()));
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
    }
}

#[async_trait]
impl Provider for GithubProvider {
    crate::impl_standard_redirect_url!("https://github.com/login/oauth/authorize");

    async fn get_user(
        &self,
        params: crate::provider::ExchangeParams<'_>,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let form_data = crate::provider::TokenExchangeForm {
            client_id: self.client_id.as_str(),
            client_secret: Some(secrecy::ExposeSecret::expose_secret(&self.client_secret)),
            code: params.auth_code,
            grant_type: None,
            redirect_uri: self.redirect_url.as_str(),
            code_verifier: params.code_verifier,
        };
        self.get_user_from_form(&form_data).await
    }

    async fn get_user_from_token(
        &self,
        access_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        // 2. Fetch user profile
        let user_res = self
            .http_client
            .get("https://api.github.com/user")
            .bearer_auth(access_token)
            .header("User-Agent", "rullst-connect") // GitHub API requires User-Agent
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        // 3. Map to generic ConnectUser
        Ok(ConnectUser {
            id: user_res["id"]
                .as_i64()
                .ok_or_else(|| crate::error::ConnectError::Provider("Missing id".to_string()))?
                .to_string(),
            name: user_res["name"]
                .as_str()
                .unwrap_or(user_res["login"].as_str().unwrap_or(""))
                .to_string(),
            email: user_res["email"].as_str().map(String::from),
            avatar_url: user_res["avatar_url"].as_str().map(String::from),
            email_verified: None,
            raw_data: user_res,
            access_token: secrecy::SecretString::from(access_token.to_string()),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://github.com/login/oauth/access_token".to_string()
    }

    crate::impl_standard_refresh_token!();

    async fn request_device_code(
        &self,
    ) -> Result<crate::user::DeviceAuthorizationResponse, crate::error::ConnectError> {
        let mut form = vec![("client_id", self.client_id.as_str())];
        if !self.scopes.is_empty() {
            form.push(("scope", self.scopes.as_str()));
        }

        let res = self
            .http_client
            .post("https://github.com/login/device/code")
            .header("Accept", "application/json")
            .form(&form)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let device_code = res["device_code"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                crate::error::ConnectError::Provider(
                    "Missing device_code from Github response".to_string(),
                )
            })?;
        let user_code = res["user_code"].as_str().map(String::from).ok_or_else(|| {
            crate::error::ConnectError::Provider(
                "Missing user_code from Github response".to_string(),
            )
        })?;
        let verification_uri = res["verification_uri"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                crate::error::ConnectError::Provider(
                    "Missing verification_uri from Github response".to_string(),
                )
            })?;

        Ok(crate::user::DeviceAuthorizationResponse {
            device_code,
            user_code,
            verification_uri,
            verification_uri_complete: res["verification_uri_complete"].as_str().map(String::from),
            expires_in: res["expires_in"].as_u64().unwrap_or(900),
            interval: res["interval"].as_u64(),
        })
    }

    async fn poll_device_token(
        &self,
        device_code: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let token_res = self
            .http_client
            .post(self.token_url())
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("device_code", device_code),
                ("grant_type", "urn:ietf:params:oauth:grant-type:device_code"),
            ])
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
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
                "Failed to get access_token during device poll. (Authorization pending?)"
                    .to_string(),
            )
        })?;

        let mut user = self.get_user_from_token(access_token).await?;
        user.refresh_token = token_res["refresh_token"]
            .as_str()
            .map(|s| secrecy::SecretString::from(s.to_string()));
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::{HttpClient, HttpRequest, HttpResponse};
    use serde_json::json;
    use std::sync::Arc;

    struct MockGithubClient;
    #[async_trait]
    impl HttpClient for MockGithubClient {
        async fn execute(
            &self,
            req: HttpRequest,
        ) -> Result<HttpResponse, crate::error::ConnectError> {
            if req.url.contains("access_token") {
                Ok(HttpResponse {
                    status: 200,
                    body: json!({
                        "access_token": "mock_token",
                        "token_type": "bearer",
                        "scope": "user:email"
                    }),
                })
            } else {
                Ok(HttpResponse {
                    status: 200,
                    body: json!({
                        "id": 1234567,
                        "login": "octocat",
                        "name": "monalisa octocat",
                        "email": "octocat@github.com",
                        "avatar_url": "https://github.com/images/error/octocat_happy.gif"
                    }),
                })
            }
        }
    }

    #[tokio::test]
    async fn test_github_get_user() {
        let provider = GithubProvider::new(
            "client_id".to_string(),
            secrecy::SecretString::from("client_secret".to_string()),
            "https://redirect.url".to_string(),
        )
        .with_http_client(Arc::new(MockGithubClient));

        let params = crate::provider::ExchangeParams {
            auth_code: "mock_code",
            code_verifier: None,
            expected_nonce: None,
        };
        let user = provider.get_user(params).await.expect("Failed to get user");
        assert_eq!(user.id, "1234567");
        assert_eq!(user.name, "monalisa octocat");
        assert_eq!(user.email, Some("octocat@github.com".to_string()));
        assert_eq!(
            user.avatar_url,
            Some("https://github.com/images/error/octocat_happy.gif".to_string())
        );
    }
}
