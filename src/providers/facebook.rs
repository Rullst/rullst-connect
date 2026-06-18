use crate::client::HttpClientExt;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(FacebookProvider, "email", "public_profile");

impl FacebookProvider {
    async fn get_user_from_form(
        &self,
        form_data: Vec<(&str, &str)>,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let token_res = self
            .http_client
            .post(self.token_url())
            .form(form_data)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let access_token = token_res["access_token"].as_str().ok_or_else(|| {
            crate::error::ConnectError::Token("Failed to get access_token".to_string())
        })?;

        let mut user = self.get_user_from_token(access_token).await?;
        user.refresh_token = token_res["refresh_token"].as_str().map(String::from);
        user.expires_in = token_res["expires_in"]
            .as_u64()
            .or_else(|| token_res["expires_in"].as_i64().map(|v| v as u64));
        Ok(user)
    }
}

#[async_trait]
impl Provider for FacebookProvider {


    crate::impl_standard_redirect_url!("https://www.facebook.com/v19.0/dialog/oauth");

    async fn get_user(
        &self,
        params: crate::provider::ExchangeParams<'_>,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let mut form_data = vec![
            ("client_id", self.client_id.as_str()),
            ("client_secret", self.client_secret.as_str()),
            ("code", params.auth_code),
            ("redirect_uri", self.redirect_url.as_str()),
        ];
        if let Some(verifier) = params.code_verifier {
            form_data.push(("code_verifier", verifier));
        }
        self.get_user_from_form(form_data).await
    }

    async fn get_user_from_token(
        &self,
        access_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let user_res = self.http_client.get("https://graph.facebook.com/v19.0/me?fields=id,name,email,picture.width(500).height(500)")
            .bearer_auth(access_token)
            .send().await?.error_for_status()?
            .json::<Value>()
            .await?;

        let avatar = user_res["picture"]["data"]["url"]
            .as_str()
            .map(String::from);

        Ok(ConnectUser {
            id: user_res["id"].as_str().map(String::from).ok_or_else(|| {
                crate::error::ConnectError::Provider("Missing user id".to_string())
            })?,
            name: user_res["name"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            email: user_res["email"].as_str().map(String::from),
            avatar_url: avatar,
            email_verified: None,
            raw_data: user_res,
            access_token: access_token.to_string(),
            refresh_token: None,
            expires_in: None,
        })
    }

    fn token_url(&self) -> String {
        "https://graph.facebook.com/v19.0/oauth/access_token".to_string()
    }

    crate::impl_standard_refresh_token!();
}
