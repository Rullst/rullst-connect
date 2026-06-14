use async_trait::async_trait;
use rullst_connect::client::{HttpClient, HttpRequest, HttpResponse};
use rullst_connect::provider::Provider;
use rullst_connect::providers::DiscordProvider;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Intercepts all requests and rewrites the host to point to the wiremock local server
struct WiremockInterceptClient {
    mock_server_url: String,
    inner: rullst_connect::client::ReqwestClient,
}

impl WiremockInterceptClient {
    fn new(mock_server_url: String) -> Self {
        Self {
            mock_server_url,
            inner: rullst_connect::client::ReqwestClient::new(),
        }
    }
}

#[async_trait]
impl HttpClient for WiremockInterceptClient {
    async fn execute(
        &self,
        mut req: HttpRequest,
    ) -> Result<HttpResponse, rullst_connect::error::ConnectError> {
        let parsed = url::Url::parse(&req.url).unwrap();
        req.url = format!("{}{}", self.mock_server_url, parsed.path());
        self.inner.execute(req).await
    }
}

#[tokio::test]
async fn test_discord_get_user_success() {
    let mock_server = MockServer::start().await;

    // 1. Mock the token exchange endpoint
    Mock::given(method("POST"))
        .and(path("/api/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock_discord_access_token",
            "token_type": "Bearer",
            "expires_in": 604800,
            "refresh_token": "mock_discord_refresh_token",
            "scope": "identify email"
        })))
        .mount(&mock_server)
        .await;

    // 2. Mock the user profile endpoint
    Mock::given(method("GET"))
        .and(path("/api/users/@me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "id": "123456789012345678",
            "username": "wumpus",
            "discriminator": "0",
            "global_name": "Wumpus",
            "avatar": "a_mock_avatar_hash",
            "bot": false,
            "system": false,
            "mfa_enabled": true,
            "banner": "a_mock_banner_hash",
            "accent_color": 16711680,
            "locale": "en-US",
            "verified": true,
            "email": "wumpus@discord.com",
            "flags": 64,
            "premium_type": 1,
            "public_flags": 64
        })))
        .mount(&mock_server)
        .await;

    let intercept_client = std::sync::Arc::new(WiremockInterceptClient::new(mock_server.uri()));
    let provider = DiscordProvider::new(
        "test_client_id".to_string(),
        "test_client_secret".to_string(),
        "http://localhost/callback".to_string(),
    )
    .with_http_client(intercept_client);

    let user = provider.get_user("discord_auth_code_123").await.unwrap();

    assert_eq!(user.id, "123456789012345678");
    assert_eq!(user.name, "wumpus");
    assert_eq!(user.email.as_deref(), Some("wumpus@discord.com"));
    assert_eq!(
        user.avatar_url.as_deref(),
        Some(
            "https://cdn.discordapp.com/avatars/123456789012345678/a_mock_avatar_hash.png?size=1024"
        )
    );
    assert_eq!(user.access_token, "mock_discord_access_token");
    assert_eq!(user.expires_in, Some(604800));
}

#[tokio::test]
async fn test_twitch_get_user_success() {
    let mock_server = MockServer::start().await;

    // 1. Mock token exchange
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "access_token": "mock_twitch_token",
            "refresh_token": "mock_twitch_refresh",
            "expires_in": 14400,
            "scope": ["user:read:email"],
            "token_type": "bearer"
        })))
        .mount(&mock_server)
        .await;

    // 2. Mock user profile
    Mock::given(method("GET"))
        .and(path("/helix/users"))
        .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
            "data": [{
                "id": "141981764",
                "login": "twitchdev",
                "display_name": "TwitchDev",
                "type": "",
                "broadcaster_type": "partner",
                "description": "Supporting the Twitch developer community",
                "profile_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png",
                "offline_image_url": "https://static-cdn.jtvnw.net/jtv_user_pictures/3f13ab61-ec78-4fe6-8481-8682cb3b0ac2-channel_offline_image-1920x1080.png",
                "view_count": 5980557,
                "email": "not-real@email.com",
                "created_at": "2016-12-14T20:32:28Z"
            }]
        })))
        .mount(&mock_server)
        .await;

    let intercept_client = std::sync::Arc::new(WiremockInterceptClient::new(mock_server.uri()));
    let provider = rullst_connect::providers::TwitchProvider::new(
        "test_client_id".to_string(),
        "test_client_secret".to_string(),
        "http://localhost/callback".to_string(),
    )
    .with_http_client(intercept_client);

    let user = provider.get_user("twitch_auth_code_123").await.unwrap();

    assert_eq!(user.id, "141981764");
    assert_eq!(user.name, "TwitchDev");
    assert_eq!(user.email.as_deref(), Some("not-real@email.com"));
    assert_eq!(
        user.avatar_url.as_deref(),
        Some(
            "https://static-cdn.jtvnw.net/jtv_user_pictures/8a6381c7-d0c0-4576-b179-38bd5ce1d6af-profile_image-300x300.png"
        )
    );
    assert_eq!(user.access_token, "mock_twitch_token");
    assert_eq!(user.refresh_token.as_deref(), Some("mock_twitch_refresh"));
    assert_eq!(user.expires_in, Some(14400));
}
