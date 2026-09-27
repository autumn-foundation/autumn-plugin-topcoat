//! The `TopcoatPlugin` builder and its `Plugin` implementation.

use std::borrow::Cow;
use std::fmt;
use std::sync::OnceLock;

use autumn_web::AppState;
use autumn_web::app::AppBuilder;
use autumn_web::plugin::Plugin;
use topcoat::router::{Router, RouterBuilder};

use crate::error::StartupError;
use crate::ingress::IngressSettings;
use crate::options::{CspCheck, CsrfBridge, NotFoundOwner};
use crate::plan::Plan;

/// The name that Autumn records for this plugin.
pub const PLUGIN_NAME: &str = "autumn-plugin-topcoat";

/// The `tracing` target of the plugin events.
pub(crate) const TRACING_TARGET: &str = "autumn_plugin_topcoat";

/// A closure that makes the Topcoat router builder from `AppState`.
pub(crate) type Factory = Box<dyn FnOnce(&AppState) -> Result<RouterBuilder, String> + Send>;

/// The Topcoat router that the plugin serves.
pub(crate) enum RouterSource {
    /// A builder that the user made.
    Builder(RouterBuilder),
    /// A closure that makes the builder at startup.
    Factory(Factory),
}

/// The state that the routes, the ingress layer and the startup hooks share.
pub(crate) struct Shared {
    pub(crate) plan: Plan,
    pub(crate) not_found: NotFoundOwner,
    pub(crate) csp_check: CspCheck,
    /// The built router. Finalize sets it at startup.
    pub(crate) router: OnceLock<Router>,
    /// The first startup error.
    pub(crate) failure: OnceLock<StartupError>,
    /// The CSRF bridge settings. Finalize sets them when Autumn CSRF is on.
    pub(crate) ingress: OnceLock<IngressSettings>,
}

impl Shared {
    pub(crate) fn new(plan: Plan, not_found: NotFoundOwner, csp_check: CspCheck) -> Self {
        Self {
            plan,
            not_found,
            csp_check,
            router: OnceLock::new(),
            failure: OnceLock::new(),
            ingress: OnceLock::new(),
        }
    }

    /// Keeps the first startup error and logs each error.
    pub(crate) fn record_failure(&self, error: StartupError) {
        let _ = error;
        unimplemented!("RED")
    }
}

/// Mounts a Topcoat router in an Autumn app.
///
/// Autumn serves the backend: typed routes, the database, sessions and the
/// middleware. Topcoat renders the frontend: each path that Autumn does not
/// route goes to Topcoat.
///
/// ```rust,no_run
/// use autumn_plugin_topcoat::TopcoatPlugin;
/// use topcoat::router::Router;
///
/// #[autumn_web::main]
/// async fn main() {
///     autumn_web::app()
///         .plugin(TopcoatPlugin::new().router(Router::builder()))
///         .run()
///         .await;
/// }
/// ```
#[must_use]
pub struct TopcoatPlugin {
    pub(crate) source: Option<RouterSource>,
    pub(crate) mount: Option<String>,
    pub(crate) excluded: Vec<String>,
    pub(crate) runtime_prefixes: Vec<String>,
    pub(crate) csrf_bridge: CsrfBridge,
    pub(crate) csp_check: CspCheck,
    pub(crate) not_found: NotFoundOwner,
}

impl TopcoatPlugin {
    /// Makes a plugin with the default options and no router.
    ///
    /// The defaults are: root mount, CSRF bridge on, CSP check `Warn`, and
    /// Autumn answers unknown paths. Set the router with [`router`](Self::router)
    /// or [`router_with`](Self::router_with).
    pub fn new() -> Self {
        Self {
            source: None,
            mount: None,
            excluded: Vec::new(),
            runtime_prefixes: Vec::new(),
            csrf_bridge: CsrfBridge::default(),
            csp_check: CspCheck::default(),
            not_found: NotFoundOwner::default(),
        }
    }

    /// Sets the Topcoat router builder.
    ///
    /// At startup, the plugin adds the Autumn state to the Topcoat app
    /// context and calls `build()`. Do not call `build()` yourself.
    pub fn router(mut self, builder: RouterBuilder) -> Self {
        self.source = Some(RouterSource::Builder(builder));
        self
    }

    /// Sets a closure that makes the Topcoat router builder at startup.
    ///
    /// The closure gets the Autumn `AppState`. Use it to read the config or
    /// to load the Topcoat asset bundle. An error stops the startup.
    ///
    /// Autumn runs the state initializers in registration order. Register
    /// this plugin after the plugins whose `AppState` extensions the closure
    /// reads.
    pub fn router_with<F, E>(mut self, factory: F) -> Self
    where
        F: FnOnce(&AppState) -> Result<RouterBuilder, E> + Send + 'static,
        E: fmt::Display,
    {
        self.source = Some(RouterSource::Factory(Box::new(move |state| {
            factory(state).map_err(|error| error.to_string())
        })));
        self
    }

    /// Mounts Topcoat under `prefix`, for example `/app`. The default is the root.
    ///
    /// Topcoat gets the full path, so declare the pages under the prefix. The
    /// plugin also serves `/_topcoat/*` for assets and runtime endpoints. An
    /// invalid prefix stops the startup.
    pub fn mount_at(mut self, prefix: impl Into<String>) -> Self {
        self.mount = Some(prefix.into());
        self
    }

    /// Makes Autumn answer 404 for paths under `prefix`, for example `/api`.
    ///
    /// Topcoat does not get these requests, and the CSRF bridge ignores them.
    /// With a prefix mount, `prefix` must be strictly under the mount.
    pub fn exclude(mut self, prefix: impl Into<String>) -> Self {
        self.excluded.push(prefix.into());
        self
    }

    /// Makes the CSRF bridge treat JSON `POST` requests under `prefix` as
    /// runtime requests.
    ///
    /// Use it for procedures and shards with a custom path, for example
    /// `#[procedure("/rpc/double")]`. These requests have no Topcoat header.
    pub fn runtime_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.runtime_prefixes.push(prefix.into());
        self
    }

    /// Sets the CSRF bridge mode. The default is [`CsrfBridge::SameOriginRuntime`].
    pub const fn csrf_bridge(mut self, mode: CsrfBridge) -> Self {
        self.csrf_bridge = mode;
        self
    }

    /// Sets the CSP check. The default is [`CspCheck::Warn`].
    pub const fn csp_check(mut self, check: CspCheck) -> Self {
        self.csp_check = check;
        self
    }

    /// Sets the framework that answers unknown paths. The default is
    /// [`NotFoundOwner::Autumn`].
    pub const fn not_found(mut self, owner: NotFoundOwner) -> Self {
        self.not_found = owner;
        self
    }
}

impl Default for TopcoatPlugin {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for TopcoatPlugin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let source = match &self.source {
            None => "none",
            Some(RouterSource::Builder(_)) => "builder",
            Some(RouterSource::Factory(_)) => "factory",
        };
        f.debug_struct("TopcoatPlugin")
            .field("router", &source)
            .field("mount", &self.mount)
            .field("excluded", &self.excluded)
            .field("runtime_prefixes", &self.runtime_prefixes)
            .field("csrf_bridge", &self.csrf_bridge)
            .field("csp_check", &self.csp_check)
            .field("not_found", &self.not_found)
            .finish()
    }
}

impl Plugin for TopcoatPlugin {
    fn name(&self) -> Cow<'static, str> {
        Cow::Borrowed(PLUGIN_NAME)
    }

    fn build(self, app: AppBuilder) -> AppBuilder {
        let _ = (app, TRACING_TARGET);
        unimplemented!("RED")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_send_static<T: Send + 'static>() {}

    #[test]
    fn new_equals_default_and_has_the_documented_defaults() {
        let plugin = TopcoatPlugin::new();
        assert_eq!(
            format!("{plugin:?}"),
            format!("{:?}", TopcoatPlugin::default())
        );
        assert_eq!(plugin.name(), PLUGIN_NAME);
        assert!(plugin.source.is_none());
        assert!(plugin.mount.is_none());
        assert_eq!(plugin.csrf_bridge, CsrfBridge::SameOriginRuntime);
        assert_eq!(plugin.csp_check, CspCheck::Warn);
        assert_eq!(plugin.not_found, NotFoundOwner::Autumn);
    }

    #[test]
    fn plugin_and_builder_are_send_and_static() {
        assert_send_static::<TopcoatPlugin>();
        assert_send_static::<RouterBuilder>();
        assert_send_static::<RouterSource>();
    }

    #[test]
    fn setters_record_the_options() {
        let plugin = TopcoatPlugin::new()
            .router(Router::builder())
            .mount_at("/app")
            .exclude("/app/api")
            .runtime_prefix("/app/rpc")
            .csrf_bridge(CsrfBridge::Off)
            .csp_check(CspCheck::Deny)
            .not_found(NotFoundOwner::Topcoat);
        let debug = format!("{plugin:?}");
        assert!(debug.contains("builder"));
        assert_eq!(plugin.mount.as_deref(), Some("/app"));
        assert_eq!(plugin.excluded, vec!["/app/api"]);
        assert_eq!(plugin.runtime_prefixes, vec!["/app/rpc"]);
        assert_eq!(plugin.csrf_bridge, CsrfBridge::Off);
        assert_eq!(plugin.csp_check, CspCheck::Deny);
        assert_eq!(plugin.not_found, NotFoundOwner::Topcoat);
        let factory = TopcoatPlugin::new().router_with(|_| Ok::<_, String>(Router::builder()));
        assert!(format!("{factory:?}").contains("factory"));
    }

    #[test]
    fn plugin_claims_no_config_section() {
        let app = autumn_web::app().plugin(TopcoatPlugin::new().router(Router::builder()));
        assert!(app.has_plugin(PLUGIN_NAME));
        assert!(!app.has_config_section("topcoat"));
    }
}
