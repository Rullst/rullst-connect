# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [9.0.1] - 2026-06-18

### Security
- **Hardcoded Credentials**: Removed hardcoded dummy credentials from Axum examples (`axum_example.rs` and `axum_server.rs`), replacing them with environment variable reads (`std::env::var`) to promote secure configuration practices.

### Performance & Maintenance
- **Form Allocation Optimization**: Replaced array slicing `.form(&[...])` with standard arrays `.form([...])` across all providers to reduce unnecessary borrowing overhead.
- **Header Construction**: Optimized `HeaderMap` construction in `ReqwestClient` to safely use `try_from` without panicking on invalid headers.
- **Redundant Clones**: Removed unnecessary `.clone()` calls on the access token in the `GoogleProvider` token exchange.
- **Macro Hygiene**: Fixed macro hygiene issue by properly scoping `#[allow(dead_code)]` in the `define_provider` macro to avoid triggering `unused_attributes` warnings in recent Rust compilers.

### Added
- **Unit Tests**: Added robust tests for `ConnectUser` serialization and deserialization.
- **Unit Tests**: Added tests for the `Connect::driver` dynamic provider factory method.
- **Unit Tests**: Added endpoints tests for the `mock_router` discovery and userinfo handlers in `mock_idp.rs`.

## [9.0.0] - 2026-06-17

### Changed (Breaking)
- **Provider API Unification**: Replaced the redundant `get_user(auth_code: &str)` and `get_user_with_pkce(...)` methods on the `Provider` trait with a single, unified `get_user(params: ExchangeParams)` method. This future-proofs the API and handles `auth_code`, `code_verifier`, and `expected_nonce` in one struct.

### Security
- **OIDC Nonce Validation**: Implemented cryptographic validation for the `nonce` claim in `GoogleProvider`, `AppleProvider`, and `OidcProvider`. The `ExchangeParams` struct now accepts an optional `expected_nonce` to prevent replay attacks during OpenID Connect flows.
- **PKCE Enforcement**: Fixed an issue where the `code_verifier` was correctly accepted by `get_user_with_pkce` but incorrectly omitted from the final token exchange POST request across multiple providers (Cognito, LinkedIn, GitHub, OIDC, Apple, Discord, Microsoft, Facebook).

### Added
- **Unit Tests**: Added comprehensive mock client testing for the `GithubProvider` to verify mapping of GitHub profile attributes.
- **Unit Tests**: Added initialization tests for `ReqwestClient::new_with_retry` under the `retry` feature flag.
- **Unit Tests**: Added missing coverage for the generic `fetch_access_token` and `fetch_refresh_token` helper methods in `src/provider.rs`.

### Performance
- **Optimized JSON Parsing**: Refactored the `GoogleProvider` token exchange to deserialize directly into a strongly-typed struct (`GoogleTokenResponse`) instead of the generic `serde_json::Value`, avoiding unnecessary allocations.

## [8.0.0] - 2026-06-15

### Changed (Breaking)
- **Pruning**: Removed 25 low-usage/unmaintained providers to focus the library completely on the 11 most robust, heavily-used core providers: Google, GitHub, Microsoft, Apple, Auth0, Cognito, Facebook, X, Discord, LinkedIn, and OIDC.
- **Security (PKCE)**: Upgraded the `Provider` trait to uniformly require PKCE natively on all providers. Implemented `get_user_with_pkce` enforcing authorization code interception attack mitigations.
- **Architecture**: Renamed the primary entry point `Socialite` to `Connect`.
- **API Optimization**: Changed `RequestBuilder::form` to accept `IntoIterator` to avoid unnecessary memory allocations. If you were passing slices via `.form(&[...])`, you must now pass arrays or vectors directly `.form([...])`.

### Changed
- **Security**: Replaced `debug_assert!` with `assert!` in Google provider to ensure configuration verification runs in release builds.
- **Security**: Upgraded CSRF `state` parameter validation in `AuthCallback` and `AuthSession` to use constant-time comparison via the `subtle` crate, mitigating timing attacks.
- **Internal**: Removed unused `dead_code` macro allowance in `macros.rs` test module.
- **Testing**: Added tests covering `ResponseWrapper::json` deserialization error paths.
- **Testing**: Added missing tests for default trait methods in `HttpClientExt` (`get` and `post`).

### Added
- **Architecture**: Renamed `Socialite` to `Connect` and implemented `Connect::driver`, a dynamic provider factory method allowing initialization of standard OAuth providers by name via string matching.
- **DRY Refactoring**: Introduced `impl_standard_redirect_url!` and `impl_standard_refresh_token!` helper macros, eliminating hundreds of lines of duplicate boilerplate across 30+ providers without introducing breaking changes to the `Provider` trait interface.
- **Testing**: Added unit tests for `fetch_refresh_token` error flows and the `exchange_and_get_user` integration helper.

### Added
- **Architecture**: Implemented `Socialite::driver`, a dynamic provider factory method allowing initialization of standard OAuth providers by name via string matching.
- **DRY Refactoring**: Introduced `impl_standard_redirect_url!` and `impl_standard_refresh_token!` helper macros, eliminating hundreds of lines of duplicate boilerplate across 30+ providers without introducing breaking changes to the `Provider` trait interface.
- **Testing**: Added unit tests for `fetch_refresh_token` error flows and the `exchange_and_get_user` integration helper.

## [7.0.2] - 2026-06-08

### Security
- **Strict CSRF Enforcement**: Axum Session extractor now strictly requires the `state` parameter in callback queries, returning a `BAD_REQUEST` error if missing, eliminating the bypass vector (FINDING-01).
- **Secure Convenience Methods**: URL-encoded the `state` and `code_challenge` parameters in default trait helper methods of `Provider` to prevent parameter injection (FINDING-02).
- **Safety Assertions**: Promoted macros credential verification guards from `debug_assert!` to standard `assert!`, ensuring validation runs in production/release builds (FINDING-03).
- **Apple Token Retrieval Hardening**: Required `access_token` presence in Apple provider token exchange rather than falling back to an empty string (FINDING-04).
- **GitHub Device Flow Validation**: Enforced presence of `device_code`, `user_code`, and `verification_uri` in GitHub device authorization flow response (FINDING-05).
- **Mock IDP Warning Documentation**: Added warnings to mock identity provider discovery and token handlers explicitly marking `alg: none` as unsafe for production (FINDING-06).

## [7.0.1] - 2026-06-06

### Security & Performance
- **Header Optimization**: Migrated 30+ providers from manual `format!()` string concatenation and Base64 encoding to native `.bearer_auth()` and `.basic_auth()` methods for robust `Authorization` header construction.
- **Async Test Hardening**: Replaced `std::sync::Mutex` with `tokio::sync::Mutex` in test mocks to prevent async lock contention. Replaced unsafe `.unwrap()` with descriptive `.expect()` and idiomatic error handling in tests and docs.

### Security
- **Token Exposure Prevention**: Migrated VK (VKontakte), Facebook, and Instagram providers to use `Authorization: Bearer <token>` HTTP headers instead of exposing `access_token` in URL query parameters, preventing leakage in server logs and proxy caches.
- **Client Secret Protection**: Migrated VK (VKontakte) token exchange from `GET` to `POST` request with a form body, protecting `client_secret` from URL exposure.
- **OIDC Signature Validation Enforcement**: Removed silent fallback to `/userinfo` in Google and generic OIDC providers when `id_token` verification/signature fails, ensuring immediate failure for invalid tokens.
- **Apple Key ID Hardening**: Refactored Apple id_token verification to prevent defaulting Key ID (`kid`) to an empty string, mitigating potential Key Confusion Attacks.
- **DoS/OOM Prevention (HttpClient)**: Imposed a 2MB maximum size limit when reading HTTP response bodies chunk-by-chunk in the default client to protect against Slowloris-style buffer attacks. Clamped `max_retries` to a maximum of 10.

### Resilience & Error Handling
- **Strict Error Handling (Phantom Users Mitigation)**: Extended the elimination of silent failures across all remaining 21 providers (including GitHub, GitLab, Apple, Google, Facebook, etc.). Crucial user identifier fields (like `id` or `sub`) no longer default to empty strings `""` or `0`, returning an explicit `ConnectError::Provider` error if essential user data is missing.
- **Graceful JWT Fallback**: Refactored `OidcProvider`'s `id_token` Key ID (`kid`) extraction to use `.and_then()` instead of `.unwrap_or_default()`, ensuring that missing `kid` headers cleanly fall back to the `/userinfo` endpoint instead of searching for an empty key.

### Added
- **Unit Tests**: Added integration/unit tests for `mock_idp.rs` to guarantee the local mock router properly simulates OAuth2 failure flows (e.g., `invalid_grant` for invalid authorization codes).
- **Unit Tests**: Added comprehensive tests in `src/error.rs` validating `.into()` conversion from standard library and third-party errors (`reqwest::Error`, `serde_json::Error`) into `ConnectError`.

## [7.0.0] - 2026-06-01

### Security & Architecture
- **Dependency Shielding (Blindagem de Dependências)**: Fully isolated the public API from external dependency leaks to protect downstream users from unexpected breaking changes:
  - Refactored `ConnectError` to hold stringified errors (`String`) instead of raw third-party types (`reqwest::Error`, `jsonwebtoken::errors::Error`, `base64::DecodeError`, etc.).
  - Implemented manual `From` conversions for internal convenience of the `?` operator without exposing raw types to consumers.
  - Restricted the visibility of the `jwks` field in `OidcProvider` from `pub` to `pub(crate)` to avoid leaking `jsonwebtoken::jwk::JwkSet` to consumers.

### Security
- **Cryptographic JWT Validation — Apple Provider**: `AppleProvider` now lazily fetches Apple's public JWKS from `https://appleid.apple.com/auth/keys` (cached via `tokio::sync::OnceCell`) and cryptographically verifies the `id_token` signature and claims on every login. Removes the previous unverified base64-decode approach.
- **Cryptographic JWT Validation — Google Provider**: `GoogleProvider` now lazily fetches Google's JWKS from `https://www.googleapis.com/oauth2/v3/certs` and validates the `id_token` signature. If validation fails (e.g. network error, unknown key), it falls back gracefully to the secure `/userinfo` API endpoint.

### Performance
- **Zero-Allocation Option Mapping**: Replaced `.as_str().unwrap_or("").to_string()` with `.as_str().map(String::from).unwrap_or_default()` across all 34 providers. This eliminates unnecessary heap allocations when a field is absent.
- **Smart Scope Serialization**: Optimized `build_oauth_params` in `src/provider.rs` to skip the `join(" ")` heap allocation entirely when only one scope is requested.
- **No-Clone Secret Generation**: Refactored `AppleClaims` to use lifetime references `AppleClaims<'a>` instead of owned `String`s, removing unnecessary clones during Apple client secret generation.

### Added
- **Mockable `CognitoProvider`**: Refactored to use `Arc<dyn HttpClient>` and exposed `with_http_client` builder method, enabling custom/mock HTTP clients for testing without a real Cognito server.
- **Mockable `OktaProvider`**: Same refactoring as above. Now fully testable offline with any custom client.
- **Mockable `AppleProvider`**: Refactored from `reqwest::Client` to `Arc<dyn HttpClient>` and exposed `with_http_client`, enabling mock-based unit testing.
- **Unit Tests — `RequestBuilder` & `ResponseWrapper`**: Comprehensive tests added to `src/client.rs` covering all builder methods and validating `error_for_status` behavior for standard OAuth error payloads, `message` fields, unknown JSON shapes, and plain-text bodies.
- **Unit Tests — `CognitoProvider` & `OktaProvider`**: Redirect URL unit tests added, verifying correct domain and parameter construction.
- **Unit Tests — `AppleProvider`**: Redirect URL and invalid token handling unit tests added.
- **Unit Tests — `GoogleProvider`**: Redirect URL unit test added.
- **Unit Tests — `OidcProvider::discover` edge cases**: Verifies correct `.well-known` URL construction with and without trailing slashes, and validates descriptive errors on missing OIDC configuration fields.

### Changed
- `ResponseWrapper` now derives `Debug` to support standard Rust test assertion patterns.
- `GoogleProvider` is now defined explicitly instead of via the `define_provider!` macro to support the additional `jwks` `OnceCell` field.



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
