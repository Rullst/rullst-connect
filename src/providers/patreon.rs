use crate::client::HttpClientExt;
use crate::error::ConnectError;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(PatreonProvider, "identity", "identity[email]");

#[async_trait]
impl Provider for PatreonProvider {
    fn redirect_url(&self) -> String {
        let mut params = crate::provider::build_oauth_params(
            &self.client_id,
            &self.redirect_url,
            &self.scopes,
            self.state.as_deref(),
            self.pkce_challenge.as_deref(),
        );
        params.append_pair("response_type", "code");
        format!(
            "https://www.patreon.com/oauth2/authorize?{}",
            params.finish()
        )
    }

    async fn get_user(
        &self,
        auth_code: &str,
    ) -> Result<crate::user::ConnectUser, crate::error::ConnectError> {
        let token = crate::provider::fetch_access_token(
            self.http_client.as_ref(),
            &self.token_url(),
            &self.client_id,
            &self.client_secret,
            auth_code,
            &self.redirect_url,
        ).await?;

        let mut user = self.get_user_from_token(&token.access_token).await?;
        user.refresh_token = token.refresh_token;
        user.expires_in = token.expires_in;
        Ok(user)
    }

    async fn get_user_from_token(&self, access_token: &str) -> Result<ConnectUser, ConnectError> {
        let user_res = self.http_client.get("https://www.patreon.com/api/oauth2/v2/identity?fields[user]=email,full_name,image_url")
            .bearer_auth(access_token)
            .send().await?.error_for_status()?
            .json::<Value>()
            .await?;

        let user_data = &user_res["data"];
        let attributes = &user_data["attributes"];

        Ok(ConnectUser {
            id: user_data["id"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing user id".to_string())
            })?,
            name: attributes["full_name"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    crate::error::ConnectError::Provider("Missing full_name".to_string())
                })?,
            email: attributes["email"].as_str().map(String::from),
            avatar_url: attributes["image_url"]
                .as_str()
                .map(String::from),
            email_verified: None,
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://www.patreon.com/api/oauth2/token".to_string()
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
        ).await?;

        let mut user = self.get_user_from_token(&token.access_token).await?;
        user.refresh_token = token.refresh_token;
        user.expires_in = token.expires_in;
        Ok(user)
    }
}
