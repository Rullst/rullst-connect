use crate::client::HttpClientExt;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(GithubProvider, "user:email");

#[async_trait]
impl Provider for GithubProvider {
    fn redirect_url(&self) -> String {
        let mut params = crate::provider::build_oauth_params(
            &self.client_id,
            &self.redirect_url,
            &self.scopes,
            self.state.as_deref(),
            self.pkce_challenge.as_deref(),
        );
        format!(
            "https://github.com/login/oauth/authorize?{}",
            params.finish()
        )
    }

    async fn get_user(&self, auth_code: &str) -> Result<ConnectUser, crate::error::ConnectError> {
        // 1. Exchange authorization code for access token
        let token_res = self
            .http_client
            .post(self.token_url())
            .header("Accept", "application/json")
            .form(&[
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
            .map(|s: &str| s.to_string());
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
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
            email: user_res["email"].as_str().map(|s: &str| s.to_string()),
            avatar_url: user_res["avatar_url"].as_str().map(|s: &str| s.to_string()),
            email_verified: None,
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://github.com/login/oauth/access_token".to_string()
    }

    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
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
                "Failed to get access_token during refresh".to_string(),
            )
        })?;

        let mut user = self.get_user_from_token(access_token).await?;
        user.refresh_token = token_res["refresh_token"].as_str().map(|s| s.to_string());
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
    }

    async fn request_device_code(
        &self,
    ) -> Result<crate::user::DeviceAuthorizationResponse, crate::error::ConnectError> {
        let mut form = vec![("client_id", self.client_id.as_str())];
        let scopes = self.scopes.join(" ");
        if !scopes.is_empty() {
            form.push(("scope", scopes.as_str()));
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

        Ok(crate::user::DeviceAuthorizationResponse {
            device_code: res["device_code"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            user_code: res["user_code"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            verification_uri: res["verification_uri"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            verification_uri_complete: res["verification_uri_complete"]
                .as_str()
                .map(|s| s.to_string()),
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
        user.refresh_token = token_res["refresh_token"].as_str().map(|s| s.to_string());
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
    }
}
