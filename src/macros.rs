/// Defines a standard OAuth2 provider struct and its builder methods.
///
/// This macro generates the boilerplate struct definition, the `new` constructor,
/// and the `with_scopes` / `with_state` builder methods.
#[macro_export]
macro_rules! define_provider {
    ($name:ident) => {
        $crate::define_provider!($name, );
    };
    ($name:ident, $($default_scope:expr),*) => {
        pub struct $name {
            pub(crate) client_id: String,
            pub(crate) client_secret: String,
            pub(crate) redirect_url: String,
            pub(crate) http_client: ::std::sync::Arc<dyn $crate::client::HttpClient>,
            pub(crate) scopes: Vec<String>,
            pub(crate) state: Option<String>,
            pub(crate) pkce_challenge: Option<String>,
        }

        impl $name {
            pub fn new(client_id: String, client_secret: String, redirect_url: String) -> Self {
                assert!(!client_id.is_empty(), "Socialite Error: client_id cannot be empty");
                assert!(!client_secret.is_empty(), "Socialite Error: client_secret cannot be empty");
                assert!(redirect_url.starts_with("http"), "Socialite Error: redirect_url must be a valid HTTP/HTTPS URL");

                Self {
                    client_id,
                    client_secret,
                    redirect_url,
                    http_client: $crate::client::DEFAULT_HTTP_CLIENT.clone(),
                    scopes: vec![$($default_scope.to_owned()),*],
                    state: None,
                    pkce_challenge: None,
                }
            }

            /// Overrides the default scopes for this provider.
            pub fn with_scopes(mut self, scopes: &[&str]) -> Self {
                self.scopes = scopes.iter().copied().map(String::from).collect();
                self
            }

            /// Sets the state parameter for CSRF protection.
            pub fn with_state(mut self, state: &str) -> Self {
                self.state = Some(state.to_owned());
                self
            }

            /// Sets the PKCE code_challenge parameter.
            pub fn with_pkce(mut self, challenge: &str) -> Self {
                self.pkce_challenge = Some(challenge.to_owned());
                self
            }

            /// Sets a custom HTTP client (e.g., for mocking, proxy, or non-reqwest backends).
            pub fn with_http_client(mut self, client: ::std::sync::Arc<dyn $crate::client::HttpClient>) -> Self {
                self.http_client = client;
                self
            }

            /// Configures the built-in HTTP client to use exponential backoff retries.
            /// This is only available when the `retry` feature is enabled.
            #[cfg(feature = "retry")]
            pub fn with_retry(mut self, max_retries: u32) -> Self {
                self.http_client = ::std::sync::Arc::new($crate::client::ReqwestClient::new_with_retry(max_retries));
                self
            }
        }
    };
}

#[macro_export]
macro_rules! impl_standard_redirect_url {
    ($url:expr) => {
        fn redirect_url(&self) -> String {
            let mut params = $crate::provider::build_oauth_params(
                $url.to_string(),
                &self.client_id,
                &self.redirect_url,
                &self.scopes,
                self.state.as_deref(),
                self.pkce_challenge.as_deref(),
            );
            params.finish()
        }
    };
}

#[macro_export]
macro_rules! impl_standard_refresh_token {
    () => {
        fn refresh_token<'life0, 'life1, 'async_trait>(
            &'life0 self,
            refresh_token: &'life1 str,
        ) -> ::core::pin::Pin<
            ::std::boxed::Box<
                dyn ::core::future::Future<
                        Output = Result<$crate::user::ConnectUser, $crate::error::ConnectError>,
                    > + ::core::marker::Send
                    + 'async_trait,
            >,
        >
        where
            'life0: 'async_trait,
            'life1: 'async_trait,
            Self: 'async_trait,
        {
            ::std::boxed::Box::pin(async move {
                $crate::provider::refresh_and_get_user(
                    self,
                    self.http_client.as_ref(),
                    &self.token_url(),
                    &self.client_id,
                    &self.client_secret,
                    refresh_token,
                )
                .await
            })
        }
    };
}

#[cfg(test)]
#[allow(dead_code)]
mod tests {
    define_provider!(DummyProvider, "default_scope1", "default_scope2");

    #[test]
    fn test_macro_generated_struct_new() {
        let provider = DummyProvider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://redirect_url".to_string(),
        );

        assert_eq!(provider.client_id, "client_id");
        assert_eq!(provider.client_secret, "client_secret");
        assert_eq!(provider.redirect_url, "http://redirect_url");
        assert_eq!(
            provider.scopes,
            vec!["default_scope1".to_string(), "default_scope2".to_string()]
        );
        assert_eq!(provider.state, None);
        assert_eq!(provider.pkce_challenge, None);
    }

    #[test]
    fn test_macro_generated_struct_with_scopes() {
        let provider = DummyProvider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://redirect_url".to_string(),
        )
        .with_scopes(&["new_scope1", "new_scope2"]);

        assert_eq!(
            provider.scopes,
            vec!["new_scope1".to_string(), "new_scope2".to_string()]
        );
    }

    #[test]
    fn test_macro_generated_struct_with_state() {
        let provider = DummyProvider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://redirect_url".to_string(),
        )
        .with_state("my_state");

        assert_eq!(provider.state, Some("my_state".to_string()));
    }

    #[test]
    fn test_macro_generated_struct_with_pkce() {
        let provider = DummyProvider::new(
            "client_id".to_string(),
            "client_secret".to_string(),
            "http://redirect_url".to_string(),
        )
        .with_pkce("my_pkce_challenge");

        assert_eq!(
            provider.pkce_challenge,
            Some("my_pkce_challenge".to_string())
        );
    }
}
