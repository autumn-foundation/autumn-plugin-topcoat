//! The `TopcoatPlugin` builder and its `Plugin` implementation.

use std::borrow::Cow;
use std::fmt;
use std::sync::{Arc, OnceLock};

use autumn_web::app::AppBuilder;
use autumn_web::plugin::Plugin;
use autumn_web::{AppState, AutumnError};
use axum::extract::Request;
use topcoat::router::{Router, RouterBuilder};

use crate::error::{ConfigError, ConfigErrors, StartupError};
use crate::finalize::finalize;
use crate::handler::forward;
use crate::ingress::{IngressLayer, IngressSettings};
use crate::options::{CspCheck, CsrfBridge, NotFoundOwner};
use crate::plan::{Plan, PlanInput, RouterPresence, plan};
use crate::routes::{any_method, mount_routes};

/// The name that Autumn records for this plugin.
pub const PLUGIN_NAME: &str = "autumn-plugin-topcoat";

/// The `tracing` target of the plugin events.
pub(crate) const TRACING_TARGET: &str = "autumn_plugin_topcoat";

/// A closure that makes the Topcoat router builder from `AppState`.
pub(crate) type Factory = Box<dyn FnOnce(&AppState) -> Result<RouterBuilder, String> + Send>;

/// The Topcoat router that the plugin serves.
pub(crate) enum RouterSource {
    /// A builder that the user made.
    Builder(Box<RouterBuilder>),
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
    pub(crate) const fn new(plan: Plan, not_found: NotFoundOwner, csp_check: CspCheck) -> Self {
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
        tracing::error!(target: TRACING_TARGET, %error, "Topcoat plugin startup error");
        let _ = self.failure.set(error);
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
        self.source = Some(RouterSource::Builder(Box::new(builder)));
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

    /// Checks the options without an Autumn app.
    ///
    /// `Plugin::build` runs the same check. When the check fails, the app
    /// stops at startup with each problem in the message.
    ///
    /// # Errors
    ///
    /// Returns each problem in the options.
    pub fn validate(&self) -> Result<(), ConfigErrors> {
        plan(&self.plan_input()).map(|_| ())
    }

    /// Returns the input of the build plan.
    fn plan_input(&self) -> PlanInput<'_> {
        let router = match &self.source {
            None => RouterPresence::Missing,
            Some(RouterSource::Builder(builder)) if builder.is_empty() => RouterPresence::Empty,
            Some(RouterSource::Builder(_)) => RouterPresence::Present,
            Some(RouterSource::Factory(_)) => RouterPresence::Factory,
        };
        PlanInput {
            mount: self.mount.as_deref(),
            excluded: &self.excluded,
            runtime_prefixes: &self.runtime_prefixes,
            router,
            csrf_bridge: self.csrf_bridge,
        }
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
        let planned = plan(&self.plan_input());
        let (plan, source) = match (planned, self.source) {
            (Ok(plan), Some(source)) => (plan, source),
            (Err(errors), _) => return fail(app, StartupError::Config(errors)),
            (Ok(_), None) => {
                return fail(
                    app,
                    StartupError::Config(ConfigErrors(vec![ConfigError::NoRouter])),
                );
            }
        };
        let method = match any_method() {
            Ok(method) => method,
            Err(error) => {
                let message = format!("the route method token is not valid: {error}");
                return fail(app, StartupError::RouterBuild { message });
            }
        };

        let shared = Arc::new(Shared::new(plan, self.not_found, self.csp_check));
        let handler = {
            let shared = Arc::clone(&shared);
            axum::routing::any(move |request: Request| {
                let shared = Arc::clone(&shared);
                async move { forward(&shared, request).await }
            })
        };
        let routes = mount_routes(&shared.plan.templates, &handler, &method);
        let register_ingress = shared.plan.register_ingress;

        let init = Arc::clone(&shared);
        let hook = Arc::clone(&shared);
        let app = app
            .routes(routes)
            .state_initializer(move |state| finalize(&init, source, state))
            .on_startup(move |_state| {
                let failure = hook.failure.get().cloned();
                async move {
                    failure.map_or(Ok(()), |error| {
                        Err(AutumnError::internal_server_error_msg(error.to_string()))
                    })
                }
            });
        if register_ingress {
            app.layer(IngressLayer::new(shared))
        } else {
            app
        }
    }
}

/// Logs `error` and registers a startup hook that returns it.
///
/// The plugin registers no route and no layer in this case.
fn fail(app: AppBuilder, error: StartupError) -> AppBuilder {
    tracing::error!(target: TRACING_TARGET, %error, "Topcoat plugin configuration error");
    app.on_startup(move |_state| {
        let message = error.to_string();
        async move { Err(AutumnError::internal_server_error_msg(message)) }
    })
}

#[cfg(test)]
mod tests;
