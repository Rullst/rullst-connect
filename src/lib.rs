pub mod client;
pub mod error;
#[cfg(any(
    feature = "axum",
    feature = "actix",
    feature = "leptos",
    feature = "rullst"
))]
pub mod extractors;
#[macro_use]
pub mod macros;
pub mod mock_idp;
pub mod pkce;
pub mod prelude;
pub mod provider;
pub mod providers;
pub mod user;

pub use error::ConnectError;

pub use provider::Provider;
pub use user::ConnectUser;

/// The main entry point for the rullst-connect library.
pub struct Connect;

impl Connect {
    /// Factory method to dynamically instantiate an OAuth provider by name.
    ///
    /// Available providers (case-insensitive):
    /// "github", "google", "facebook", "gitlab", "discord", "linkedin", "x", "microsoft"
    ///
    /// Note: Providers requiring specialized configuration (like Apple, Auth0, Cognito, and Okta)
    /// must be instantiated manually.
    pub fn driver(
        name: &str,
        client_id: String,
        client_secret: secrecy::SecretString,
        redirect_url: String,
    ) -> Result<Box<dyn Provider>, crate::error::ConnectError> {
        let name = name.to_lowercase();
        let provider: Box<dyn Provider> = match name.as_str() {
            "github" => Box::new(crate::providers::GithubProvider::new(
                client_id,
                client_secret,
                redirect_url,
            )),
            "google" => Box::new(crate::providers::GoogleProvider::new(
                client_id,
                client_secret,
                redirect_url,
            )),
            "facebook" => Box::new(crate::providers::FacebookProvider::new(
                client_id,
                client_secret,
                redirect_url,
            )),
            "discord" => Box::new(crate::providers::DiscordProvider::new(
                client_id,
                client_secret,
                redirect_url,
            )),
            "linkedin" => Box::new(crate::providers::LinkedinProvider::new(
                client_id,
                client_secret,
                redirect_url,
            )),
            "x" => Box::new(crate::providers::XProvider::new(
                client_id,
                client_secret,
                redirect_url,
            )),
            "microsoft" => Box::new(crate::providers::MicrosoftProvider::new(
                client_id,
                client_secret,
                redirect_url,
            )),
            "apple" | "auth0" | "cognito" | "oidc" => {
                return Err(crate::error::ConnectError::Provider(format!(
                    "Provider '{}' requires custom configuration (domain or key_id) and cannot be instantiated via the generic driver factory. Please instantiate it directly.",
                    name
                )));
            }
            _ => {
                return Err(crate::error::ConnectError::Provider(format!(
                    "Unknown provider: {}",
                    name
                )));
            }
        };
        Ok(provider)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_driver_factory() {
        let github = Connect::driver(
            "github",
            "id".to_string(),
            secrecy::SecretString::from("secret".to_string()),
            "http://url".to_string(),
        );
        assert!(github.is_ok());

        let apple = Connect::driver(
            "apple",
            "id".to_string(),
            secrecy::SecretString::from("secret".to_string()),
            "http://url".to_string(),
        );
        assert!(apple.is_err());

        let unknown = Connect::driver(
            "unknown",
            "id".to_string(),
            secrecy::SecretString::from("secret".to_string()),
            "http://url".to_string(),
        );
        assert!(unknown.is_err());
    }
}
