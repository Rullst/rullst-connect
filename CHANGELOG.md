# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [6.1.5] - 2026-05-31

### Changed
- **Dependency Updates**: 
  - `leptos_router` `0.7` → `0.8`

--- 

## [6.1.3] - 2026-05-31

### Changed
- **Dependency Updates**: Updated all direct dependencies to use flexible versioning for automatic patch/minor updates:
  - `async-trait` `0.1.89` → `0.1`
  - `base64` `0.22.1` → `0.22`
  - `jsonwebtoken` `10.4.0` → `10`
  - `rand` `0.10.1` → `0.10`
  - `reqwest` `0.13.4` → `0.13` (maintained for compatibility with reqwest-middleware)
  - `serde` `1.0.228` → `1`
  - `serde_json` `1.0.150` → `1`
  - `sha2` `0.11.0` → `0.11`
  - `thiserror` `2.0.18` → `2`
  - `tokio` `1.52.3` → `1`
  - `url` `2.5.8` → `2.5`
  - `axum` `0.8.9` → `0.8`
  - `actix-web` `4.13.0` → `4`
  - `leptos_router` `0.6` → `0.7`
  - `serde_urlencoded` `0.7.1` → `0.7`
  - `reqwest-middleware` `0.5.2` → `0.5`
  - `reqwest-retry` `0.9.1` → `0.9`
  - `tower-sessions` `0.15.0` → `0.15`
  - `wiremock` `0.6.5` → `0.6` (dev)

## [6.1.2] - 2026-05-31

### Changed
- **Dependency Updates**: All direct dependencies updated to their latest stable versions:
  - `rand` `0.8` → `0.10.1`
  - `reqwest` `0.13.3` → `0.13.4`
  - `actix-web` `4.9.0` → `4.13.0`
  - `tower-sessions` `0.13.0` → `0.15.0`
  - `wiremock` `0.6.2` → `0.6.5` (dev)

### Internal
- **rand 0.10 Migration** (`src/pkce.rs`): Updated PKCE code to the new `rand 0.10` API — replaced `distributions::Alphanumeric` with `distr::Alphanumeric`, `thread_rng()` with `rng()`, and imported `RngExt` trait for `sample_iter` support.

## [6.1.1] - 2026-05-30

### Fixed
- **Formatting Cleanup**: Reflowed several Rust modules to satisfy `cargo fmt -- --check` and keep CI green.
- **Publish Workflow**: Corrected the crates.io tag filter and added manual workflow dispatch for releases.
- **Release Documentation**: Added a dedicated release guide and aligned the README with the publish flow.

## [6.1.0] - 2026-05-30

### Added
- **OIDC Fast-Path Provider (`OidcProvider`):** Added a generic provider that automatically downloads the OpenID configuration via `.well-known/openid-configuration` and sets up endpoints instantly.
- **Enterprise-Grade Observability:** Native integration with `tracing` crate. Highly detailed spans during token exchanges and profile fetching.
- **Strict Profile Normalization:** Enforced strict typing for `UniversalProfile` (`ConnectUser`), ensuring fields like `email_verified` exist consistently across all 35+ providers.
- **Automated CSRF Protection (`AuthSession`):** Added an Axum Session extractor (behind `axum-session` feature flag) with `tower-sessions` to automatically generate, store, and validate OAuth `state` securely.
- **Native Apple Secret Generation:** `AppleProvider` now dynamically generates the JWT `client_secret` on the fly using a `.p8` Private Key, eliminating tedious script generation for developers.
- **Local Mock IdP:** Added a built-in mock identity provider router (behind `mock-idp` feature flag) powered by Axum, enabling full E2E testing without internet access or rate limits.
- **Device Authorization Flow (RFC 8628):** Support for headless CLI tools and Smart TVs with new `request_device_code()` and `poll_device_token()` methods, fully implemented for GitHub.
- **Cryptographic OIDC Signature Validation:** `OidcProvider` now automatically fetches the provider's JWKS Public Keys and cryptographically verifies the RSA signature of the `id_token` for maximum enterprise security.
- **Unified Provider Errors**: Replaced panic/opaque errors with `ProviderApiError`. HTTP 400s now gracefully parse OAuth 2.0 standard JSON errors (`error`, `error_description`).
- **ORM Integration**: Added the `IntoDatabaseUser` helper trait to easily transform the universal profile into your database models.

### Changed
- **Avatar Standardization**: Improved avatar resolution for Discord (upscaled to 1024px), Google (upscaled to 400px), and X/Twitter (stripped `_normal` suffix for original quality).

### Fixed
- **Mock IdP Build:** Added the missing `base64::Engine` import in `src/mock_idp.rs` so the mock identity provider builds cleanly with the current `base64` API.
- **GitHub Integration Test:** Updated the token error assertion to match the actual `ConnectError::ProviderApiError` shape returned by the client.
- **Clippy Cleanup:** Moved the `src/extractors.rs` test module to the end of the file to satisfy `clippy::items_after_test_module`.
- **Twitch Provider Safety:** Removed the remaining production `unwrap()` in `src/providers/twitch.rs` and now return a proper error when the user payload is empty.
- **Rustdoc Hygiene:** Fixed the bare URL warning in `src/providers/cognito.rs` by formatting it as a proper rustdoc link.

## [5.2.3] - 2026-05-29

### Fixed
- **Formatting**: Fixed trailing blank lines left over by `cargo fix` to appease the strict `-D warnings` on `cargo fmt`.

## [5.2.2] - 2026-05-29

### Fixed
- **Clean Code**: Removed unused `url::form_urlencoded` imports left over from the v5.2.0 refactor, fixing `-D warnings` on the `clippy` CI check.

## [5.2.1] - 2026-05-29

### Fixed
- **CI/CD**: Fixed GitHub Actions permission issue for `rustsec/audit-check` that caused workflow failures.
- **Formatting**: Fixed `cargo fmt` errors on `src/lib.rs`, `src/macros.rs`, and integration tests.

## [5.2.0] - 2026-05-29

### Added
- **Leptos Support**: Integrated Leptos support! By enabling the `leptos` feature, the `AuthCallback` extractor now seamlessly implements `leptos_router::Params`.
- **HTTP Client Agnostic**: The provider traits and builder methods now allow passing a custom `HttpClient` through `.with_http_client(...)`.
- **HTTP Proxy Support**: With the agnostic HTTP client interface, users can now provide a proxy-configured client to navigate locked-down environments easily.

### Refactored
- **URL Generation Boilerplate**: Cleaned up the codebase by removing massive code duplication across all 35 providers for URL generation (`client_id`, `redirect_uri`, `scope`, `state`, `pkce` logic is now unified).

## [5.1.0] - 2026-05-28

### Added
- **Automatic CSRF Validation**: The `AuthCallback` extractor now includes a `verify_state(&self, session_state: &str)` method to automatically secure OAuth flows against CSRF attacks.
- **Refresh Token Support**: Added `token_url()` and `refresh_token(token: &str)` methods to the `Provider` trait and implemented them across all 35 providers, allowing developers to automatically renew expired tokens natively.

### Fixed
- **Testing Dependencies**: Added `serde_urlencoded` to `dev-dependencies` to fix a major compilation bug running the test suite on `main`.

### Security
- Maintained zero `unsafe` footprint while ensuring standard parameter passing for URL token generation and token revocation across providers.

## [5.0.2] - 2026-05-27

### Performance
- **Optimized String allocations**: Replaced `String::new()` with `String::with_capacity(256)` in all 33 providers' `redirect_url` methods, reducing unnecessary reallocations and improving performance.

### Developer Experience
- **Fixed README example**: Corrected compilation bug in the README.md code example (line 103) where the `Err` branch was incorrectly placed inside the `Ok` block.

### Maintenance
- **Removed dead code**: Deleted `src/utils.rs` file which was no longer used after the PR-29 refactoring that inlined URL parameter serialization logic directly into providers.

### Internal
- **Code cleanup**: Removed unused module imports and references to the deleted `utils.rs` module from `lib.rs`.

### Compatibility
- **Breaking Changes**: None
- **API Changes**: None
- **Migration Guide**: No migration required - fully backward compatible with v5.0.1

## [5.0.1] - 2026-05-27

### Added
- **Tokens returned on User**: `ConnectUser` now contains `access_token`, `refresh_token`, and `expires_in` fields so you can interact with the provider's API immediately.
- **Frontend/Mobile Integrations**: Added `get_user_from_token(access_token)` to all providers. This allows your backend to securely fetch the user profile when the OAuth flow is handled natively on the frontend (e.g. mobile apps, React, Vue).
- **Framework Integrations (Axum & Actix)**: Added `axum` and `actix-web` optional features in `Cargo.toml`. Provides native extractors (`AuthCallback`) for seamless URL parsing in route handlers.
- **Token Revocation**: New `revoke_token` method on the `Provider` trait for direct logout at the provider level (reference implementation added for Google).
- **Mocking Tools (TDD)**: Added `MockProvider` to the library to facilitate offline unit testing.
- **Continuous Integration**: Added GitHub Actions (Publish to Crates.io) to automate new version deployments via Tags.
- **Native OIDC Support**: OIDC providers (like Google and Apple) now feature a "Fast Path" that decodes the `id_token` directly via base64, extracting name, email, and photo instantly without making a secondary HTTP request! A massive performance boost.
- **PKCE Support (Proof Key for Code Exchange)**: All providers now have native support for modern PKCE security via the `.with_pkce(code_challenge)` builder method.
- **Prelude Module (`rullst_connect::prelude::*`)**: Added a prelude module for unified imports (ideal for developers and AI assistants).

### Changed
- **Architectural Macros**: All providers now use the internal `define_provider!` macro, which centralizes constructors, state, PKCE, scopes, and reduces hundreds of lines of boilerplate.
- All dependencies have been updated to their latest compatible versions.
- Cleaned up compiler warnings related to unused variables across providers.

## [0.4.0] - Previous stable version
- Initial open-source release with 33 OAuth2 providers supported.
- Standardized `ConnectUser` and async support.
