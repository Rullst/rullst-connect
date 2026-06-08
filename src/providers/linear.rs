use crate::client::HttpClientExt;
use crate::error::ConnectError;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(LinearProvider, "read");

#[async_trait]
impl Provider for LinearProvider {
    fn redirect_url(&self) -> String {
        let mut params = crate::provider::build_oauth_params(
            &self.client_id,
            &self.redirect_url,
            &self.scopes,
            self.state.as_deref(),
            self.pkce_challenge.as_deref(),
        );
        params.append_pair("response_type", "code");
        format!("https://linear.app/oauth/authorize?{}", params.finish())
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
        // Linear exposes user info via GraphQL
        let query = "{ viewer { id name email avatarUrl } }";
        let user_res = self
            .http_client
            .post("https://api.linear.app/graphql")
            .bearer_auth(access_token)
            .json(serde_json::json!({ "query": query }))
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let viewer = &user_res["data"]["viewer"];

        Ok(ConnectUser {
            id: viewer["id"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| crate::error::ConnectError::Provider("Missing id".to_string()))?,
            name: viewer["name"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            email: viewer["email"].as_str().map(String::from),
            avatar_url: viewer["avatarUrl"].as_str().map(String::from),
            email_verified: None,
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://api.linear.app/oauth/token".to_string()
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
