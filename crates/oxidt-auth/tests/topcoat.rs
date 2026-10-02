//! A Topcoat page sees the login state the mounted axum auth routes wrote.
#![cfg(feature = "topcoat")]

use axum::routing::post;
use oxidt_auth::LoggedInData;
use topcoat::{
    Result,
    context::Cx,
    router::{
        Router,
        request::Request,
        route,
        tower::{TowerLayer, TowerRoute},
    },
};
use tower_sessions::{MemoryStore, Session, SessionManagerLayer};

#[route(GET "/me")]
async fn me(cx: &Cx) -> Result<String> {
    let user = oxidt_auth::topcoat::user_session(cx).await?;
    Ok(user.data().map_or("anonymous".into(), |d| d.email))
}

async fn test_login(session: Session) {
    let data = LoggedInData {
        id: "1".into(),
        sub: "sub".into(),
        email: "ada@example.com".into(),
        username: "ada".into(),
        avatar_url: None,
        id_token: "token".into(),
    };
    oxidt_auth::login(&session, &data).await.unwrap();
}

fn app() -> Router {
    let auth = axum::Router::new().route("/auth/test-login", post(test_login));
    Router::builder()
        .route(me)
        .route(TowerRoute::any("/auth/{*rest}", auth))
        .layer(TowerLayer::new(
            SessionManagerLayer::new(MemoryStore::default()).with_secure(false),
        ))
        .build()
}

async fn body(res: topcoat::router::response::Response) -> String {
    let bytes = topcoat::router::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    String::from_utf8(bytes.to_vec()).unwrap()
}

#[tokio::test]
async fn page_reads_session_written_by_axum_route() {
    let app = app();

    let res = app
        .handle(Request::get("/me").body(().into()).unwrap())
        .await;
    assert_eq!(body(res).await, "anonymous");

    let res = app
        .handle(
            Request::post("/auth/test-login")
                .header("host", "localhost")
                .header("origin", "http://localhost")
                .body(().into())
                .unwrap(),
        )
        .await;
    assert!(res.status().is_success(), "login: {}", res.status());
    let cookie = res.headers()["set-cookie"].to_str().unwrap();
    let cookie = cookie.split(';').next().unwrap().to_owned();

    let res = app
        .handle(
            Request::get("/me")
                .header("cookie", cookie)
                .body(().into())
                .unwrap(),
        )
        .await;
    assert_eq!(body(res).await, "ada@example.com");
}

#[cfg(feature = "local-login")]
mod login_page {
    use super::body;
    use oxidt_auth::topcoat::local_login_page;
    use topcoat::{
        Result,
        router::{Router, page, request::Request},
        view::{View, view},
    };

    #[page("/login")]
    async fn login() -> Result<impl View> {
        Ok(view! { local_login_page(redirect_url: "/home") })
    }

    async fn render(accept_language: &str) -> String {
        let app = Router::builder().page(login).build();
        let req = Request::get("/login")
            .header("accept-language", accept_language)
            .body(().into())
            .unwrap();
        body(app.handle(req).await).await
    }

    #[tokio::test]
    async fn renders_every_step_and_the_unescaped_script() {
        let html = render("en").await;
        for step in [
            "email",
            "passkey",
            "passkey-retry",
            "offer",
            "tos",
            "password",
            "otp",
            "verifying",
            "success",
        ] {
            assert!(
                html.contains(&format!("data-step=\"{step}\"")),
                "missing {step}"
            );
        }
        assert!(html.contains("data-redirect=\"/home\""));
        assert!(html.contains("<script>// Drives the Topcoat"));
        assert!(html.contains("type=\"application/json\">{}</script>"));
    }

    #[tokio::test]
    async fn negotiates_german() {
        let html = render("de").await;
        assert!(html.contains("Anmelden oder Konto erstellen"));
        assert!(
            html.contains("\"Back\""),
            "German catalog is shipped to the script"
        );
    }
}
