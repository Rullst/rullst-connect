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

/// The main entry point for the Socialite library.
pub struct Socialite;

impl Socialite {
    // TODO: In the future, this will act as a factory (e.g., driver(name: &str) -> Box<dyn Provider>)
}
