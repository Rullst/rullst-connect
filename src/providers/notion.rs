use crate::client::HttpClientExt;
use crate::error::ConnectError;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(NotionProvider);

#[async_trait]
impl Provider for NotionProvider {
    fn redirect_url(&self) -> String {
        let mut params = crate::provider::build_oauth_params(
            &self.client_id,
            &self.redirect_url,
            &self.scopes,
            self.state.as_deref(),
            self.pkce_challenge.as_deref(),
        );
        params.append_pair("response_type", "code");
        params.append_pair("owner", "user");
        format!(
            "https://api.notion.com/v1/oauth/authorize?{}",
            params.finish()
        )
    }

    async fn get_user(&self, auth_code: &str) -> Result<ConnectUser, ConnectError> {
        let token_res = self
            .http_client
            .post(self.token_url())
            .basic_auth(&self.client_id, Some(&self.client_secret))
            .json(serde_json::json!({
                "grant_type": "authorization_code",
                "code": auth_code,
                "redirect_uri": self.redirect_url.as_str()
            }))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let owner = &token_res["owner"]["user"];

        let access_token = token_res["access_token"]
            .as_str()
            .map(String::from)
            .ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing access_token".to_string())
            })?;

        Ok(ConnectUser {
            id: owner["id"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing user id".to_string())
            })?,
            name: owner["name"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing user name".to_string())
            })?,
            email: owner["person"]["email"].as_str().map(String::from),
            avatar_url: owner["avatar_url"].as_str().map(String::from),
            access_token,
            refresh_token: token_res["refresh_token"].as_str().map(String::from),
            expires_in: token_res["expires_in"]
                .as_u64()
                .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64)),
            email_verified: None,
            raw_data: token_res, // Notion returns user data right in the token response
        })
    }

    async fn get_user_from_token(&self, access_token: &str) -> Result<ConnectUser, ConnectError> {
        let user_res = self
            .http_client
            .get("https://api.notion.com/v1/users/me")
            .bearer_auth(access_token)
            .header("Notion-Version", "2022-06-28")
            .send()
            .await?
            .json::<Value>()
            .await?;

        let user = if user_res["type"].as_str() == Some("bot") {
            &user_res["bot"]["owner"]["user"]
        } else {
            &user_res
        };

        Ok(ConnectUser {
            id: user["id"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing user id".to_string())
            })?,
            name: user["name"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing user name".to_string())
            })?,
            email: user["person"]["email"].as_str().map(String::from),
            avatar_url: user["avatar_url"].as_str().map(String::from),
            email_verified: None,
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://api.notion.com/v1/oauth/token".to_string()
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
