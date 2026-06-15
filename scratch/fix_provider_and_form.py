import os

provider_path = 'src/provider.rs'
with open(provider_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Fix fetch_access_token
content = content.replace(
    """pub async fn fetch_access_token(
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_url: &str,
) -> Result<crate::user::OAuthTokenResponse, crate::error::ConnectError> {
    let form = [
        ("grant_type", "authorization_code"),
        ("client_id", client_id),
        ("client_secret", client_secret),
        ("code", code),
        ("redirect_uri", redirect_url),
    ];

    let res = client
        .post(token_url)
        .form(&form)""",
    """pub async fn fetch_access_token(
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_url: &str,
    code_verifier: Option<&str>,
) -> Result<crate::user::OAuthTokenResponse, crate::error::ConnectError> {
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

    let res = client
        .post(token_url)
        .form(form)"""
)

# Fix exchange_and_get_user
content = content.replace(
    """pub async fn exchange_and_get_user<P>(
    provider: &P,
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_url: &str,
) -> Result<ConnectUser, crate::error::ConnectError>""",
    """pub async fn exchange_and_get_user<P>(
    provider: &P,
    client: &dyn crate::client::HttpClient,
    token_url: &str,
    client_id: &str,
    client_secret: &str,
    code: &str,
    redirect_url: &str,
    code_verifier: Option<&str>,
) -> Result<ConnectUser, crate::error::ConnectError>"""
)
content = content.replace(
    "fetch_access_token(client, token_url, client_id, client_secret, code, redirect_url).await?;",
    "fetch_access_token(client, token_url, client_id, client_secret, code, redirect_url, code_verifier).await?;"
)

with open(provider_path, 'w', encoding='utf-8') as f:
    f.write(content)

# Fix .form(&[ -> .form([ and form(&form) -> form(form) in all providers
providers_dir = 'src/providers'
if os.path.exists(providers_dir):
    for f in os.listdir(providers_dir):
        if f.endswith('.rs'):
            path = os.path.join(providers_dir, f)
            with open(path, 'r', encoding='utf-8') as fp:
                c = fp.read()
            c = c.replace('.form(&[', '.form([')
            c = c.replace('.form(&form)', '.form(form)')
            c = c.replace('.form(&vec!', '.form(vec!')
            with open(path, 'w', encoding='utf-8') as fp:
                fp.write(c)

print("Fixed provider.rs and form calls in providers!")
