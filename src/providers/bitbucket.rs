use crate::client::HttpClientExt;
use crate::provider::Provider;
use crate::user::ConnectUser;
use async_trait::async_trait;
use serde_json::Value;

crate::define_provider!(BitbucketProvider);

#[async_trait]
impl Provider for BitbucketProvider {
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
            "https://bitbucket.org/site/oauth2/authorize?{}",
            params.finish()
        )
    }

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
        )
        .await
    }

    async fn get_user_from_token(
        &self,
        access_token: &str,
    ) -> Result<ConnectUser, crate::error::ConnectError> {
        let user_res = self
            .http_client
            .get("https://api.bitbucket.org/2.0/user")
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let emails_res = self
            .http_client
            .get("https://api.bitbucket.org/2.0/user/emails")
            .bearer_auth(access_token)
            .send()
            .await?
            .error_for_status()?
            .json::<Value>()
            .await?;

        let email = emails_res["values"]
            .as_array()
            .and_then(|vals| {
                vals.iter()
                    .find(|v| v["is_primary"].as_bool().unwrap_or(false))
            })
            .and_then(|v| v["email"].as_str())
            .map(String::from);

        Ok(ConnectUser {
            id: user_res["account_id"]
                .as_str()
                .map(String::from)
                .ok_or_else(|| {
                    crate::error::ConnectError::Provider("Missing user id".to_string())
                })?,
            name: user_res["display_name"]
                .as_str()
                .map(String::from)
                .unwrap_or_default(),
            email,
            avatar_url: user_res["links"]["avatar"]["href"]
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
        "https://bitbucket.org/site/oauth2/access_token".to_string()
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
