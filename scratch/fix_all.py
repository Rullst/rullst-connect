import os
import re

providers = ['microsoft.rs', 'discord.rs', 'auth0.rs', 'cognito.rs', 'linkedin.rs', 'x.rs', 'mock.rs']

base_dir = r"c:\Users\venelouis\Desktop\REPOS\rullst-connect\src\providers"

for prov in providers:
    filepath = os.path.join(base_dir, prov)
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 1. Remove get_user_with_pkce
    pattern_pkce = r"    async fn get_user_with_pkce\([\s\S]*?\}\n\n"
    content = re.sub(pattern_pkce, "", content)
    
    # 2. Replace get_user
    # Note: X.rs might have `_auth_code` in mock etc.
    pattern_user = r"    async fn get_user\([\s\S]*?\}\n"
    
    replacement = """    async fn get_user(
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
    }\n"""
    
    content = re.sub(pattern_user, replacement, content)
    
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(content)
    
    print(f"Fixed {prov}")
