//! An Autumn app that serves a JSON API and a Topcoat frontend.
//!
//! Run it:
//!
//! ```sh
//! cargo run --example host
//! ```
//!
//! Then open `http://localhost:3000/`. The API is at `/api/greeting`.

use autumn_plugin_topcoat::{TopcoatPlugin, autumn};
use autumn_web::prelude::*;
use topcoat::context::Cx;
use topcoat::router::{Router, page};
use topcoat::view::{View, view};

/// A backend route: Autumn serves it.
#[get("/api/greeting")]
#[public]
async fn greeting() -> Json<serde_json::Value> {
    Json(serde_json::json!({ "message": "Hello from Autumn" }))
}

/// A frontend page: Topcoat renders it with data from Autumn.
#[page("/")]
async fn home(cx: &Cx) -> topcoat::Result<impl View> {
    let profile = autumn::config(cx)?.profile.clone().unwrap_or_default();
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <body>
                <h1>"Autumn backend, Topcoat frontend"</h1>
                <p>"Profile: " (profile)</p>
            </body>
        </html>
    })
}

#[autumn_web::main]
async fn main() {
    Box::pin(
        autumn_web::app()
            .routes(routes![greeting])
            .plugin(
                TopcoatPlugin::new()
                    .router(Router::builder().page(home))
                    .exclude("/api"),
            )
            .run(),
    )
    .await;
}
