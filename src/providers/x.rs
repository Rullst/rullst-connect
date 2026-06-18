use crate::client::HttpClientExt;
use crate::error::ConnectError;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(XProvider, "users.read", "tweet.read");

#[async_trait]
impl Provider for XProvider {
    crate::impl_standard_redirect_url!("https://twitter.com/i/oauth2/authorize");

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
            .get("https://api.twitter.com/2/users/me?user.fields=profile_image_url")
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let data = &user_res["data"];

        Ok(ConnectUser {
            id: data["id"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| crate::error::ConnectError::Provider("Missing id".to_string()))?,
            name: data["name"].as_str().map(String::from).unwrap_or_default(),
            email: None, // X v2 does not return email via this endpoint by default
            avatar_url: data["profile_image_url"]
                .as_str()
                .map(|s: &str| s.replace("_normal.", ".")),
            email_verified: None,
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://api.twitter.com/2/oauth2/token".to_string()
    }

    crate::impl_standard_refresh_token!();
}
