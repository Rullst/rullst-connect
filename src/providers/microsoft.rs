use crate::client::HttpClientExt;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(MicrosoftProvider, "User.Read");

#[async_trait]
impl Provider for MicrosoftProvider {
    async fn get_user_with_pkce(
        &self,
        auth_code: &str,
        _code_verifier: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        self.get_user(auth_code).await
    }

    crate::impl_standard_redirect_url!(
        "https://login.microsoftonline.com/common/oauth2/v2.0/authorize"
    );

    async fn get_user(
        &self,
        auth_code: &str,
    ) -> Result<crate::user::ConnectUser, crate::error::ConnectError> {
        crate::provider::exchange_and_get_user(
            self,
            self.http_client.as_ref(),
            &self.token_url(),
            &self.client_id,
            &self.client_secret,
            auth_code,
            &self.redirect_url,
            None,
        )
        .await
    }

    async fn get_user_from_token(
        &self,
        access_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let user_res = self
            .http_client
            .get("https://graph.microsoft.com/v1.0/me")
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        Ok(ConnectUser {
            id: user_res["id"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing user id".to_string())
            })?,
            name: user_res["displayName"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    crate::error::ConnectError::Provider("Missing user displayName".to_string())
                })?,
            email: user_res["mail"]
                .as_str()
                .or_else(|| user_res["userPrincipalName"].as_str())
                .map(String::from),
            avatar_url: None, // Requires a separate request to /me/photo/$value
            email_verified: None,
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://login.microsoftonline.com/common/oauth2/v2.0/token".to_string()
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
