import os
import re

p = 'src/provider.rs'
with open(p, 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Fix fetch_access_token
old_fetch = """pub async fn fetch_access_token(
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_url: &str,
) -> Result<Oauth2TokenResponse, crate::error::ConnectError> {
    let token_res = client
        .post(token_url)
        .form(&[
            ("grant_type", "authorization_code"),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("code", code),
            ("redirect_uri", redirect_url),
        ])"""

new_fetch = """pub async fn fetch_access_token(
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_url: &str,
    code_verifier: Option<&str>,
) -> Result<Oauth2TokenResponse, crate::error::ConnectError> {
    let mut form = vec![
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("redirect_uri", redirect_url),
    ];
    if let Some(verifier) = code_verifier {
        form.push(("code_verifier", verifier));
    }

    let token_res = client
        .post(token_url)
        .form(form)"""

content = content.replace(old_fetch, new_fetch)

# 2. Fix exchange_and_get_user
old_exchange = """pub async fn exchange_and_get_user<P>(
    provider: &P,
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_url: &str,
) -> Result<ConnectUser, crate::error::ConnectError>"""

new_exchange = """pub async fn exchange_and_get_user<P>(
    provider: &P,
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_url: &str,
    code_verifier: Option<&str>,
) -> Result<ConnectUser, crate::error::ConnectError>"""

content = content.replace(old_exchange, new_exchange)
content = content.replace(
    "fetch_access_token(client, token_url, client_id, client_secret, code, redirect_url)\n        .await?;",
    "fetch_access_token(client, token_url, client_id, client_secret, code, redirect_url, code_verifier)\n        .await?;"
)
content = content.replace(
    "fetch_access_token(client, token_url, client_id, client_secret, code, redirect_url).await?;",
    "fetch_access_token(client, token_url, client_id, client_secret, code, redirect_url, code_verifier).await?;"
)

# 3. Fix fetch_refresh_token to use array literal
old_refresh = """.form(&[
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ])"""

new_refresh = """.form([
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("refresh_token", refresh_token),
            ("grant_type", "refresh_token"),
        ])"""
content = content.replace(old_refresh, new_refresh)

with open(p, 'w', encoding='utf-8') as f:
    f.write(content)

print("Updated provider.rs successfully!")
