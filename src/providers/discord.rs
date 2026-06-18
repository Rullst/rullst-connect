use crate::client::HttpClientExt;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(DiscordProvider, "identify", "email");

#[async_trait]
impl Provider for DiscordProvider {
    crate::impl_standard_redirect_url!("https://discord.com/api/oauth2/authorize");

    async fn get_user(
        &self,
        params: crate::provider::ExchangeParams<'_>,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let form_data = crate::provider::TokenExchangeForm {
            client_id: self.client_id.as_str(),
            client_secret: Some(self.client_secret.as_str()),
            code: params.auth_code,
            grant_type: Some("authorization_code"),
            redirect_uri: self.redirect_url.as_str(),
            code_verifier: params.code_verifier,
        };
        crate::provider::exchange_and_get_user(
            self,
            self.http_client.as_ref(),
            &self.token_url(),
            &form_data,
            params.expected_nonce,
        )
        .await
    }

    async fn get_user_from_token(
        &self,
        access_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let user_res = self
            .http_client
            .get("https://discord.com/api/users/@me")
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let id = user_res["id"]
            .as_str()
            .map(String::from)
            .unwrap_or_default();
        let avatar_hash = user_res["avatar"].as_str();
        let avatar_url = avatar_hash.map(|hash| {
            format!(
                "https://cdn.discordapp.com/avatars/{}/{}.png?size=1024",
                id, hash
            )
        });

        Ok(ConnectUser {
            id,
            name: user_res["username"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            email: user_res["email"].as_str().map(String::from),
            avatar_url,
            email_verified: user_res["verified"].as_bool(),
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://discord.com/api/oauth2/token".to_string()
    }

    async fn refresh_token(
        &self,
        refresh_token: &str,
    ) -> Result<crate::user::ConnectUser, crate::error::ConnectError> {
        crate::provider::refresh_and_get_user(
            self,
            self.http_client.as_ref(),
            &self.token_url(),
            &self.client_id,
            &self.client_secret,
            refresh_token,
        )
        .await
    }
}
