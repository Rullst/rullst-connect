use axum::{
    Router,
    extract::Query,
    response::{Html, IntoResponse, Redirect},
    routing::get,
};
use rullst_connect::provider::Provider;
use rullst_connect::providers::github::GithubProvider;
use rullst_connect::providers::google::GoogleProvider;
use serde::Deserialize;

#[derive(Deserialize)]
struct AuthRequest {
    code: String,
}

// Em um projeto real, isso viria de variáveis de ambiente (.env)
const GOOGLE_CLIENT_ID: &str = "SEU_GOOGLE_CLIENT_ID";
const GOOGLE_CLIENT_SECRET: &str = "SEU_GOOGLE_CLIENT_SECRET";
const GITHUB_CLIENT_ID: &str = "SEU_GITHUB_CLIENT_ID";
const GITHUB_CLIENT_SECRET: &str = "SEU_GITHUB_CLIENT_SECRET";

#[tokio::main]
async fn main() {
    let app = Router::new()
        .route("/", get(index))
        .route("/auth/google", get(login_google))
        .route("/auth/google/callback", get(callback_google))
        .route("/auth/github", get(login_github))
        .route("/auth/github/callback", get(callback_github));

    println!("🚀 Servidor rodando em http://localhost:3000");
    let listener = tokio::net::TcpListener::bind("127.0.0.1:3000")
        .await
        .unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn index() -> Html<&'static str> {
    Html(
        r#"
        <h1>Rullst Connect Example</h1>
        <a href="/auth/google">Login com Google</a><br><br>
        <a href="/auth/github">Login com GitHub</a>
    "#,
    )
}

// ==========================================
// GOOGLE
// ==========================================
async fn login_google() -> Redirect {
    let provider = GoogleProvider::new(
        GOOGLE_CLIENT_ID.to_string(),
        GOOGLE_CLIENT_SECRET.to_string(),
        "http://localhost:3000/auth/google/callback".to_string(),
    );
    Redirect::to(&provider.redirect_url())
}

async fn callback_google(Query(query): Query<AuthRequest>) -> impl IntoResponse {
    let provider = GoogleProvider::new(
        GOOGLE_CLIENT_ID.to_string(),
        GOOGLE_CLIENT_SECRET.to_string(),
        "http://localhost:3000/auth/google/callback".to_string(),
    );

    let params = rullst_connect::provider::ExchangeParams {
        auth_code: &query.code,
        ..Default::default()
    };
    match provider.get_user(params).await {
        Ok(user) => Html(format!(
            "<h2>Bem-vindo, {}!</h2><p>Email: {:?}</p><p>ID: {}</p><img src='{:?}'>",
            user.name, user.email, user.id, user.avatar_url
        )),
        Err(e) => Html(format!("Erro no login: {:?}", e)),
    }
}

// ==========================================
// GITHUB
// ==========================================
async fn login_github() -> Redirect {
    let provider = GithubProvider::new(
        GITHUB_CLIENT_ID.to_string(),
        GITHUB_CLIENT_SECRET.to_string(),
        "http://localhost:3000/auth/github/callback".to_string(),
    );
    Redirect::to(&provider.redirect_url())
}

async fn callback_github(Query(query): Query<AuthRequest>) -> impl IntoResponse {
    let provider = GithubProvider::new(
        GITHUB_CLIENT_ID.to_string(),
        GITHUB_CLIENT_SECRET.to_string(),
        "http://localhost:3000/auth/github/callback".to_string(),
    );

    let params = rullst_connect::provider::ExchangeParams {
        auth_code: &query.code,
        ..Default::default()
    };
    match provider.get_user(params).await {
        Ok(user) => Html(format!(
            "<h2>Bem-vindo, {}!</h2><p>Email: {:?}</p><p>ID: {}</p><img src='{:?}'>",
            user.name, user.email, user.id, user.avatar_url
        )),
        Err(e) => Html(format!("Erro no login: {:?}", e)),
    }
}
