import os, re

files = [
    'auth0.rs', 'cognito.rs', 'discord.rs', 'linkedin.rs', 'microsoft.rs',
    'apple.rs', 'facebook.rs', 'github.rs', 'google.rs', 'oidc.rs', 'x.rs'
]

for f in files:
    path = os.path.join('src', 'providers', f)
    if not os.path.exists(path): continue
    
    with open(path, 'r', encoding='utf-8') as fp:
        content = fp.read()
        
    # 1. Add `None` to fetch_access_token and exchange_and_get_user
    # They take 8 arguments now instead of 7 (for exchange) and 7 instead of 6 (for fetch).
    # Since the last argument is redirect_url, we find `&self.redirect_url,` and append `None,`
    content = re.sub(r'(&self\.redirect_url,?)(\s*\))', r'\1 None,\2', content)
    
    # 2. Inject get_user_with_pkce into custom providers
    # If the provider doesn't have get_user_with_pkce, add it right above `async fn get_user(`
    if "get_user_with_pkce" not in content and f not in ['auth0.rs', 'cognito.rs', 'discord.rs', 'linkedin.rs', 'microsoft.rs']:
        content = re.sub(
            r'(\s+)(async fn get_user\()', 
            r'\1async fn get_user_with_pkce(&self, auth_code: &str, _code_verifier: &str) -> Result<ConnectUser, crate::error::ConnectError> {\n        self.get_user(auth_code).await\n    }\n\1\2', 
            content
        )

    with open(path, 'w', encoding='utf-8') as fp:
        fp.write(content)

print("Done fixing all 11 providers!")
