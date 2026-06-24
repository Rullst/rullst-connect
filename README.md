# Rullst Connect 🦀

[![Crates.io](https://img.shields.io/crates/v/rullst-connect.svg)](https://crates.io/crates/rullst-connect)
[![Downloads](https://img.shields.io/crates/d/rullst-connect.svg)](https://crates.io/crates/rullst-connect)
[![Documentation](https://docs.rs/rullst-connect/badge.svg)](https://docs.rs/rullst-connect)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust Version](https://img.shields.io/badge/rustc-1.75+-lightgray.svg)](https://blog.rust-lang.org/2023/12/28/Rust-1.75.0.html)

**Rullst Connect** is an elegant, async-first, and Developer Experience (DX) focused OAuth2 authentication library for Rust. It simplifies the integration of social logins into your Rust web applications, providing a standardized interface across multiple providers.

## 🛡️ Quality & Security Audits

| CI & Coverage | Security & Analysis | Formal & Advanced Testing |
| :--- | :--- | :--- |
| [![CI Build](https://github.com/venelouis/rullst-connect/actions/workflows/ci.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions/workflows/ci.yml)<br>[![Coverage](https://codecov.io/gh/venelouis/rullst-connect/graph/badge.svg)](https://codecov.io/gh/venelouis/rullst-connect)<br>[![Spellcheck](https://github.com/venelouis/rullst-connect/actions/workflows/spellcheck.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions/workflows/spellcheck.yml) | [![CodeQL](https://github.com/venelouis/rullst-connect/actions/workflows/codeql.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions/workflows/codeql.yml)<br>[![Cargo Deny](https://github.com/venelouis/rullst-connect/actions/workflows/cargo-deny.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions/workflows/cargo-deny.yml)<br>[![Machete](https://github.com/venelouis/rullst-connect/actions/workflows/machete.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions/workflows/machete.yml) | [![Fuzz Testing](https://github.com/venelouis/rullst-connect/actions/workflows/fuzz.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions/workflows/fuzz.yml)<br>[![Mutants](https://github.com/venelouis/rullst-connect/actions/workflows/mutants.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions/workflows/mutants.yml)<br>[![Kani](https://github.com/venelouis/rullst-connect/actions/workflows/kani.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions/workflows/kani.yml) |
| [![Publish](https://github.com/venelouis/rullst-connect/actions/workflows/publish.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions) | [![Semver Checks](https://github.com/venelouis/rullst-connect/actions/workflows/semver.yml/badge.svg)](https://github.com/venelouis/rullst-connect/actions/workflows/semver.yml) | [![Zero Panics](https://img.shields.io/badge/Panics-0-success.svg)](AUDIT.md)<br>[![Audit: 10/10](https://img.shields.io/badge/Audit-10%2F10-success.svg)](AUDIT.md) |

## ✨ Features

- 🚀 **Async & Fast**: Built on top of `tokio` and `reqwest`.
- 🧩 **Standardized**: All providers return a unified `ConnectUser` struct.
- 🛡️ **Type-Safe**: Robust error handling using `thiserror` (`ConnectError`).
- 🔌 **Framework Agnostic**: Works seamlessly with Rullst, Axum, Actix, Leptos, Dioxus, or any other framework.
- 🔐 **Enterprise Security**: Built-in OIDC Discovery, JWKS validation, and automated CSRF `tower-sessions`.
- 📺 **Device Flow**: Native RFC 8628 support for headless CLI and Smart TV auth.
- 🛠️ **Testing**: Embedded Mock IdP router for seamless offline local E2E testing.

> 📚 **Important Documents:**
> - [CHANGELOG.md](CHANGELOG.md): See what's new.
> - [ISSUES](https://github.com/venelouis/rullst-connect/issues): Any issue? Please report.
> - [ROADMAP.md](ROADMAP.md): Discover our path.
> - [AUDIT.md](AUDIT.md): Complete security, performance, and maintainability audit report.

## 📦 Supported Providers

Official support for 11 core providers:

1. **Google**
2. **GitHub**
3. **Microsoft / Azure AD**
4. **Apple** (Sign in with Apple)
5. **Auth0**
6. **AWS Cognito**
7. **Facebook**
8. **X (Twitter)** (Strict PKCE requirement)
9. **Discord**
10. **LinkedIn**
11. **OIDC (OpenID Connect Custom Provider)**

## 🛠️ Installation

Add the package to your `Cargo.toml`. If you use **Rullst**, **Axum**, **Actix**, or **Leptos**, you can enable their specific features for native Extractor support!

You can either run:
```bash
cargo add rullst-connect
```

Or manually add it to your `Cargo.toml`:
```toml
[dependencies]
rullst-connect = "10.0.1"
tokio = { version = "1.52", features = ["full"] }
```

## 🚀 Quick Start

### 1. Initialize the Provider
Choose your provider and pass your credentials and callback URL:

```rust
use rullst_connect::prelude::*;

let github = GithubProvider::new(
    "YOUR_CLIENT_ID".to_string(),
    "YOUR_CLIENT_SECRET".to_string(),
    "http://localhost:3000/auth/github/callback".to_string(),
);
```

### 2. Redirect the User
Get the authorization URL and redirect your user:

```rust
let url = github.redirect_url();
// Example in Axum: return Redirect::temporary(&url);
```

### 3. Handle the Callback & Get User
When the user returns to your callback URL with a `code` query parameter, exchange it for a `ConnectUser`:

```rust
let params = rullst_connect::provider::ExchangeParams {
    auth_code: code,
    ..Default::default()
};
match github.get_user(params).await {
    Ok(user) => {
        println!("Welcome, {}!", user.name);
        println!("Email: {:?}", user.email);
        println!("Avatar: {:?}", user.avatar_url);
    }
    Err(_) => return (StatusCode::INTERNAL_SERVER_ERROR, "Failed to get user".to_string()),
}
```

### 🛡️ CSRF Protection (State Parameter)

To prevent Cross-Site Request Forgery (CSRF) attacks, you should generate a secure random string, save it in a session/cookie, and pass it to the provider.

```rust
// 1. Generate a random state string and save it in the session
let state = "random_secure_string";

// 2. Get the authorization URL with the state parameter using the builder
let url = github.with_state(state).redirect_url();
// return Redirect::temporary(&url);

// 3. In the callback route, verify if the query param `state` matches your session!
// If you are using the optional `axum` or `actix` features, you can use `verify_state`:
// params.verify_state(&state_from_session)?;
```

### 🔄 Refreshing Tokens

If an access token expires, you can seamlessly renew it without asking the user to login again by using their `refresh_token`:

```rust
let refreshed_user = github.refresh_token("existing_refresh_token_string").await?;
// Tokens are wrapped in `secrecy::SecretString` to prevent accidental log leakage ([REDACTED]).
// When you need to send it to an API, expose it explicitly:
use secrecy::ExposeSecret;
let raw_token = refreshed_user.access_token.expose_secret();
println!("Successfully refreshed token securely!");
```

### 🔒 PKCE Support (v9.0.0+)

All providers natively support PKCE (Proof Key for Code Exchange) to mitigate authorization code interception attacks. Some providers like **X (Twitter) v2** strictly require it.

```rust
use rullst_connect::pkce::generate_pkce;

// 1. Generate challenge and verifier
let (code_verifier, code_challenge) = generate_pkce();

// 2. Save `code_verifier` in the user's session or a secure HttpOnly cookie!

// 3. Get the URL with PKCE natively using the builder pattern
let auth_url = provider.with_pkce(&code_challenge).redirect_url();

// 4. In the callback route, fetch the user using the saved verifier:
let params = rullst_connect::provider::ExchangeParams {
    auth_code: &code,
    code_verifier: Some(&code_verifier),
    ..Default::default()
};
let user = provider.get_user(params).await.unwrap();
```

## 🧑‍💻 Full Example with Axum

You can find a complete working server using the **Axum** framework in the examples directory. Just run:

```bash
cargo run --example axum_server
```

## 📦 Releasing a New Version

This project uses `cargo-release` to automate version bumps, README synchronization, and CHANGELOG management.
The publish workflow in `.github/workflows/publish.yml` runs when a `vX.Y.Z` tag is pushed, and it can also be triggered manually from GitHub Actions.

To release a new version, simply run:

```bash
# install it first if you haven't: cargo install cargo-release
cargo release patch --execute  # for v1.0.x patches
cargo release minor --execute  # for v1.x.0 features
cargo release major --execute  # for vX.0.0 breaking changes
```

This will automatically bump versions, tag the release, and push to GitHub, triggering the crates.io publish workflow.

For the exact release checklist and what to do next time, see [RELEASING.md](RELEASING.md).

## 🤝 Contributing

Feel free to open Issues and submit Pull Requests! Want to add a new provider? It's easy! Just implement the `Provider` trait.

<!--
## Contributors ✨
Thanks!

<a href="https://github.com/Rullst/rullst-connect/graphs/contributors">
  <img src="https://contrib.rocks/image?repo=Rullst/rullst-connect" />
</a>
-->

## 📄 License

This project is licensed under the MIT License.
