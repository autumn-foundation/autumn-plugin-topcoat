//! Shared helpers for the integration tests.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    missing_docs
)]

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::{Arc, Mutex};

use autumn_web::config::AutumnConfig;
use autumn_web::test::{TestApp, TestClient, TestResponse};

/// A config for the `test` profile, with CSRF off (the TestApp default).
pub fn config() -> AutumnConfig {
    let mut config = AutumnConfig::default();
    config.profile = Some("test".into());
    config
}

/// A config with Autumn CSRF on.
pub fn csrf_config() -> AutumnConfig {
    let mut config = config();
    config.security.csrf.enabled = true;
    config
}

/// Returns the value of the cookie `name` from the `Set-Cookie` headers.
pub fn set_cookie(response: &TestResponse, name: &str) -> Option<String> {
    response
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case("set-cookie"))
        .find_map(|(_, value)| {
            let pair = value.split(';').next()?;
            let (key, value) = pair.split_once('=')?;
            (key.trim() == name).then(|| value.trim().to_owned())
        })
}

/// Returns the header values called `name`.
pub fn header_values(response: &TestResponse, name: &str) -> Vec<String> {
    response
        .headers
        .iter()
        .filter(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.clone())
        .collect()
}

/// Builds the test app and returns the panic text, or `None` when it builds.
pub fn build_panic(app: TestApp) -> Option<String> {
    match catch_unwind(AssertUnwindSafe(move || app.build())) {
        Ok(_client) => None,
        Err(payload) => Some(
            payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_owned()))
                .unwrap_or_default(),
        ),
    }
}

/// Builds the test app and panics with a clear message when it fails.
pub fn build(app: TestApp) -> TestClient {
    app.build()
}

/// A `tracing` capture of the plugin events: `(level, message)` pairs.
#[derive(Clone, Default)]
pub struct Events(pub Arc<Mutex<Vec<(tracing::Level, String)>>>);

impl Events {
    /// Counts the events at `level`.
    pub fn count(&self, level: tracing::Level) -> usize {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(l, _)| *l == level)
            .count()
    }

    /// Returns all messages at `level`.
    pub fn messages(&self, level: tracing::Level) -> Vec<String> {
        self.0
            .lock()
            .unwrap()
            .iter()
            .filter(|(l, _)| *l == level)
            .map(|(_, m)| m.clone())
            .collect()
    }
}

struct Capture(Events);

struct Visitor<'a>(&'a mut String);

impl tracing::field::Visit for Visitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        use std::fmt::Write;
        let _ = write!(self.0, "{}={:?} ", field.name(), value);
    }
}

impl<S: tracing::Subscriber> tracing_subscriber::Layer<S> for Capture {
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        _ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if event.metadata().target() == "autumn_plugin_topcoat" {
            let mut text = String::new();
            event.record(&mut Visitor(&mut text));
            self.0
                .0
                .lock()
                .unwrap()
                .push((*event.metadata().level(), text));
        }
    }
}

/// Runs `f` with a subscriber that captures the plugin events on this thread.
pub fn capture<T>(f: impl FnOnce() -> T) -> (T, Events) {
    use tracing_subscriber::layer::SubscriberExt;
    let events = Events::default();
    let subscriber = tracing_subscriber::registry().with(Capture(events.clone()));
    let value = tracing::subscriber::with_default(subscriber, f);
    (value, events)
}
