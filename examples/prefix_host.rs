//! An Autumn app that mounts a Topcoat frontend under `/app`.
//!
//! Run it:
//!
//! ```sh
//! cargo run --example prefix_host
//! ```
//!
//! Then open `http://localhost:3000/app`. Autumn owns all other paths, and
//! the host route `/{slug}` does not conflict with the plugin routes.

use autumn_plugin_topcoat::TopcoatPlugin;
use autumn_web::prelude::*;
use topcoat::router::{Router, page};
use topcoat::view::{View, view};

/// A backend route with a root capture: Autumn serves it.
#[get("/{slug}")]
#[public]
async fn slug(Path(slug): Path<String>) -> String {
    format!("Autumn page {slug}")
}

/// A frontend page under the mount path.
#[page("/app")]
async fn home() -> topcoat::Result<impl View> {
    Ok(view! {
        <!DOCTYPE html>
        <html>
            <body>
                <h1>"Topcoat under /app"</h1>
            </body>
        </html>
    })
}

#[autumn_web::main]
async fn main() {
    autumn_web::app()
        .routes(routes![slug])
        .plugin(
            TopcoatPlugin::new()
                .mount_at("/app")
                .router(Router::builder().page(home)),
        )
        .run()
        .await;
}
