import os, re

# 1. Fix src/provider.rs
p = 'src/provider.rs'
with open(p, 'r', encoding='utf-8') as f:
    content = f.read()

# Remove default impl from trait
content = re.sub(
    r'async fn get_user_with_pkce\(\s*&self,\s*auth_code:\s*&str,\s*_code_verifier:\s*&str,\s*\)\s*->\s*Result<ConnectUser,\s*crate::error::ConnectError>\s*\{\s*self\.get_user\(auth_code\)\.await\s*\}',
    'async fn get_user_with_pkce(\n        &self,\n        auth_code: &str,\n        code_verifier: &str,\n    ) -> Result<ConnectUser, crate::error::ConnectError>;',
    content
)

# Inject into DummyProvider
if "impl Provider for DummyProvider {" in content and "async fn get_user_with_pkce" not in content.split("impl Provider for DummyProvider {")[1]:
    content = content.replace("impl Provider for DummyProvider {\n", "impl Provider for DummyProvider {\n    async fn get_user_with_pkce(&self, auth_code: &str, _code_verifier: &str) -> Result<ConnectUser, crate::error::ConnectError> { self.get_user(auth_code).await }\n")

# Inject into MockProvider
if "impl Provider for MockProvider {" in content and "async fn get_user_with_pkce" not in content.split("impl Provider for MockProvider {")[1]:
    content = content.replace("impl Provider for MockProvider {\n", "impl Provider for MockProvider {\n    async fn get_user_with_pkce(&self, auth_code: &str, _code_verifier: &str) -> Result<ConnectUser, crate::error::ConnectError> { self.get_user(auth_code).await }\n")

with open(p, 'w', encoding='utf-8') as f:
    f.write(content)


# 2. Fix src/providers/*.rs
files = [
    'auth0.rs', 'cognito.rs', 'discord.rs', 'linkedin.rs', 'microsoft.rs',
    'apple.rs', 'facebook.rs', 'github.rs', 'google.rs', 'oidc.rs', 'x.rs'
]

for f in files:
    path = os.path.join('src', 'providers', f)
    if not os.path.exists(path): continue
    
    with open(path, 'r', encoding='utf-8') as fp:
        content = fp.read()
        
    # Append None to fetch_access_token and exchange_and_get_user
    content = re.sub(r'(&self\.redirect_url,?)(\s*\))', r'\1 None,\2', content)
    
    # Inject get_user_with_pkce into the provider implementation
    impl_match = re.search(r'impl Provider for \w+ \{', content)
    if impl_match:
        impl_block_start = impl_match.end()
        after_impl = content[impl_block_start:]
        if "async fn get_user_with_pkce" not in after_impl and "crate::impl_standard_get_user_with_pkce!();" not in after_impl:
            # We insert it right after the impl block starts
            content = content[:impl_block_start] + "\n    async fn get_user_with_pkce(&self, auth_code: &str, _code_verifier: &str) -> Result<ConnectUser, crate::error::ConnectError> { self.get_user(auth_code).await }\n" + content[impl_block_start:]

    with open(path, 'w', encoding='utf-8') as fp:
        fp.write(content)

# 3. Fix mock.rs
mock_path = 'src/providers/mock.rs'
if os.path.exists(mock_path):
    with open(mock_path, 'r', encoding='utf-8') as f:
        m = f.read()
    if "async fn get_user_with_pkce" not in m:
        m = m.replace("impl Provider for MockProvider {\n", "impl Provider for MockProvider {\n    async fn get_user_with_pkce(&self, auth_code: &str, _code_verifier: &str) -> Result<ConnectUser, crate::error::ConnectError> { self.get_user(auth_code).await }\n")
    with open(mock_path, 'w', encoding='utf-8') as f:
        f.write(m)

print("All clean!")
