//! Client address, streaming, WebSocket upgrades and compression. Covers AC-17 and AC-18.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic, missing_docs)]

mod common;

use std::future::Future;
use std::io::Read;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use autumn_plugin_topcoat::TopcoatPlugin;
use autumn_web::test::TestApp;
use axum::extract::ConnectInfo;
use bytes::Bytes;
use http_body::Frame;
use http_body_util::BodyExt;
use tokio::sync::Notify;
use topcoat::context::Cx;
use topcoat::router::request::remote_addr;
use topcoat::router::response::Response;
use topcoat::router::{Body, Router, page, route};
use topcoat::runtime::RouterBuilderRuntimeExt;
use topcoat::view::{View, view};
use tower::ServiceExt;

static RELEASE: Notify = Notify::const_new();

/// A body with two chunks. The second chunk waits for [`RELEASE`].
struct TwoChunks {
    sent_first: bool,
    wait: Option<Pin<Box<dyn Future<Output = ()> + Send>>>,
    done: bool,
}

impl http_body::Body for TwoChunks {
    type Data = Bytes;
    type Error = std::convert::Infallible;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        if !self.sent_first {
            self.sent_first = true;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"first")))));
        }
        if self.done {
            return Poll::Ready(None);
        }
        let wait = self
            .wait
            .get_or_insert_with(|| Box::pin(RELEASE.notified()));
        match wait.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.done = true;
                Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"second")))))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

#[route(GET "/addr")]
async fn addr(cx: &Cx) -> topcoat::Result<String> {
    Ok(remote_addr(cx).map_or_else(|| "none".to_owned(), |a| a.to_string()))
}

#[route(GET "/stream")]
async fn stream() -> topcoat::Result<Response> {
    Ok(Response::new(Body::new(TwoChunks {
        sent_first: false,
        wait: None,
        done: false,
    })))
}

#[page("/live")]
async fn live() -> topcoat::Result<impl View> {
    Ok(view! { <p>"live"</p> })
}

#[page("/big")]
async fn big() -> topcoat::Result<impl View> {
    let text = "Topcoat renders the frontend. ".repeat(20);
    Ok(view! { <p>(text)</p> })
}

fn plugin() -> TopcoatPlugin {
    TopcoatPlugin::new().router(
        Router::builder()
            .route(addr)
            .route(stream)
            .page(live)
            .page(big)
            .runtime(),
    )
}

async fn body_text(response: axum::response::Response) -> String {
    let bytes = response.into_body().collect().await.unwrap().to_bytes();
    String::from_utf8_lossy(&bytes).into_owned()
}

#[tokio::test]
async fn remote_addr_comes_from_connect_info() {
    let router = TestApp::new().plugin(plugin()).build().into_router();
    let request = |info: Option<SocketAddr>| {
        let mut request = http::Request::get("/addr")
            .body(axum::body::Body::empty())
            .unwrap();
        if let Some(info) = info {
            request.extensions_mut().insert(ConnectInfo(info));
        }
        request
    };
    let peer: SocketAddr = "127.0.0.1:5555".parse().unwrap();
    let with = router.clone().oneshot(request(Some(peer))).await.unwrap();
    assert_eq!(body_text(with).await, "127.0.0.1:5555");
    let without = router.clone().oneshot(request(None)).await.unwrap();
    assert_eq!(body_text(without).await, "none");
    let synthetic: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let unix = router.oneshot(request(Some(synthetic))).await.unwrap();
    assert_eq!(
        body_text(unix).await,
        "none",
        "port 0 is the Unix socket placeholder"
    );
}

#[tokio::test]
async fn streamed_chunks_are_not_buffered() {
    let router = TestApp::new().plugin(plugin()).build().into_router();
    let request = http::Request::get("/stream")
        .body(axum::body::Body::empty())
        .unwrap();
    let response = tokio::time::timeout(Duration::from_secs(5), router.oneshot(request))
        .await
        .expect("the response head arrives before the stream ends")
        .unwrap();
    let mut body = response.into_body();
    let first = tokio::time::timeout(Duration::from_secs(5), body.frame())
        .await
        .expect("the first chunk arrives before the stream ends")
        .unwrap()
        .unwrap();
    assert_eq!(first.into_data().unwrap(), Bytes::from_static(b"first"));
    RELEASE.notify_one();
    let rest = body.collect().await.unwrap().to_bytes();
    assert_eq!(rest, Bytes::from_static(b"second"));
}

#[tokio::test]
async fn websocket_upgrades_pass_the_autumn_stack() {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    let router = TestApp::new().plugin(plugin()).build().into_router();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let mut request = format!("ws://{address}/live")
        .into_client_request()
        .unwrap();
    request
        .headers_mut()
        .insert("sec-websocket-protocol", "topcoat-runtime".parse().unwrap());
    let (socket, response) = tokio::time::timeout(
        Duration::from_secs(5),
        tokio_tungstenite::connect_async(request),
    )
    .await
    .expect("the handshake ends in time")
    .expect("the upgrade succeeds");
    assert_eq!(response.status(), 101);
    assert_eq!(
        response.headers().get("sec-websocket-protocol").unwrap(),
        "topcoat-runtime"
    );
    drop(socket);
    server.abort();
}

#[tokio::test]
async fn two_compressors_give_one_encoding() {
    let mut config = common::config();
    config.compression.enabled = true;
    let client = TestApp::new().config(config).plugin(plugin()).build();
    let response = client
        .get("/big")
        .header("accept-encoding", "gzip")
        .send()
        .await;
    response.assert_ok();
    assert_eq!(
        common::header_values(&response, "content-encoding"),
        vec!["gzip"]
    );
    let mut text = String::new();
    flate2::read::GzDecoder::new(response.body.as_slice())
        .read_to_string(&mut text)
        .expect("the body decodes once");
    assert!(text.contains("Topcoat renders the frontend."), "{text}");
}
