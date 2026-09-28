//! Content-Security-Policy analysis for Topcoat.
//!
//! Autumn sets the `Content-Security-Policy` header on each response when the
//! policy is not empty. The Topcoat runtime needs three things from that
//! policy:
//!
//! - `'unsafe-eval'` in `script-src`, because the runtime compiles
//!   expressions with `new Function`.
//! - `'unsafe-inline'` for script elements, because streamed HTML swaps are
//!   inline scripts. A nonce, a hash or `'strict-dynamic'` disables
//!   `'unsafe-inline'`.
//! - Same-origin script elements and connections, because the runtime loads
//!   a module from `/_topcoat/assets` and calls the server.
//!
//! # Contract
//!
//! - `analyze` never panics. An empty or blank policy turns off CSP and has no
//!   findings.
//! - A policy string can hold more than one policy, separated by commas. The
//!   findings are the union of the findings of each policy.
//! - Directive names and keywords are ASCII case-insensitive. The first
//!   directive with a name wins.
//! - `EvalBlocked`: `script-src` (else `default-src`) exists and has no
//!   `'unsafe-eval'`.
//! - `TrustedTypesBlockEval`: `require-trusted-types-for` has `'script'`.
//! - `InlineBlocked`: `script-src-elem` (else `script-src`, else
//!   `default-src`) exists and has `'strict-dynamic'`, a nonce or a hash, or
//!   has no `'unsafe-inline'`. The reason is the first of these, in this order.
//! - `ModuleBlocked`: the script element list exists and has
//!   `'strict-dynamic'` or permits no same-origin script.
//! - `ConnectBlocked`: `connect-src` (else `default-src`) exists and permits
//!   no same-origin connection.
//! - `SandboxBlocksScripts`: `sandbox` exists and has no `allow-scripts`.
//! - `SandboxOpaqueOrigin`: `sandbox` exists and has no `allow-same-origin`.
//! - A list permits same-origin loads if it has `'self'`, `*`, an `http:` or
//!   `https:` scheme source, or a host source. The check does not compare
//!   the host with the app host. An unquoted keyword, for example `self`, is
//!   not a host source.
//! - [`recommended_csp`] has no findings.

use autumn_web::security::HeadersConfig;

/// The nonce-aware default policy of Autumn 0.7, with its placeholder.
const AUTUMN_NONCE_TEMPLATE: &str = "default-src 'self'; img-src 'self' data:; style-src 'self' \
     'nonce-AUTUMN_CSP_NONCE'; script-src 'self' 'nonce-AUTUMN_CSP_NONCE'; connect-src 'self'; \
     form-action 'self'; frame-ancestors 'none'; base-uri 'self'";

/// One way that a policy blocks Topcoat.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CspFinding {
    /// `script-src` (or `default-src`) has no `'unsafe-eval'`. The runtime
    /// cannot compile expressions.
    EvalBlocked,
    /// `require-trusted-types-for 'script'` blocks `new Function`.
    TrustedTypesBlockEval,
    /// The policy blocks inline scripts. Streamed swaps and redirects do not run.
    InlineBlocked(InlineBlock),
    /// The runtime module from `/_topcoat/assets` cannot load.
    ModuleBlocked,
    /// The runtime cannot connect to the server.
    ConnectBlocked,
    /// `sandbox` without `allow-scripts` blocks all scripts.
    SandboxBlocksScripts,
    /// `sandbox` without `allow-same-origin` gives the page an opaque origin.
    /// The CSRF bridge and the Topcoat origin check then refuse runtime requests.
    SandboxOpaqueOrigin,
}

/// Why the policy blocks inline scripts.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum InlineBlock {
    /// `'strict-dynamic'` disables `'unsafe-inline'`.
    NeutralizedByStrictDynamic,
    /// A nonce or a hash disables `'unsafe-inline'`.
    NeutralizedByNonceOrHash,
    /// The list has no `'unsafe-inline'`.
    MissingUnsafeInline,
}

/// The result of [`analyze`].
#[non_exhaustive]
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct CspReport {
    /// `true` if the policy is empty, so the browser applies no policy.
    pub disabled: bool,
    /// The problems, in a stable order, without duplicates.
    pub findings: Vec<CspFinding>,
}

impl CspReport {
    /// Returns `true` if the analysis finds no problem.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

impl std::fmt::Display for CspFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::EvalBlocked => "script-src (or default-src) has no 'unsafe-eval'",
            Self::TrustedTypesBlockEval => "require-trusted-types-for 'script' blocks new Function",
            Self::InlineBlocked(InlineBlock::NeutralizedByStrictDynamic) => {
                "'strict-dynamic' disables inline scripts"
            }
            Self::InlineBlocked(InlineBlock::NeutralizedByNonceOrHash) => {
                "a nonce or a hash disables 'unsafe-inline'"
            }
            Self::InlineBlocked(InlineBlock::MissingUnsafeInline) => {
                "script elements have no 'unsafe-inline'"
            }
            Self::ModuleBlocked => "the policy blocks same-origin module scripts",
            Self::ConnectBlocked => "connect-src blocks same-origin connections",
            Self::SandboxBlocksScripts => "sandbox without allow-scripts blocks all scripts",
            Self::SandboxOpaqueOrigin => {
                "sandbox without allow-same-origin gives the page an opaque origin"
            }
        };
        f.write_str(text)
    }
}

/// Analyzes a policy string for Topcoat.
#[must_use]
pub fn analyze(policy: &str) -> CspReport {
    let policies = parse(policy);
    let mut report = CspReport {
        disabled: policies.is_empty(),
        findings: Vec::new(),
    };
    for policy in &policies {
        for finding in policy.findings() {
            if !report.findings.contains(&finding) {
                report.findings.push(finding);
            }
        }
    }
    report
}

/// Returns the Autumn default policy with the changes that Topcoat needs.
///
/// The result is the Autumn default with
/// `script-src 'self' 'unsafe-inline' 'unsafe-eval'`. Copy it into
/// `security.headers.content_security_policy`. These sources decrease the
/// XSS protection of the full app.
#[must_use]
pub fn recommended_csp() -> String {
    patch(&autumn_web::security::default_content_security_policy()).policy
}

/// A construct that the patch cannot fix, because the fix removes a source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum PatchBlocker {
    StrictDynamic,
    NonceOrHash,
    TrustedTypes,
    Sandbox,
}

/// The result of [`patch`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Patched {
    /// The policy with the added sources.
    pub(crate) policy: String,
    /// The constructs that still block Topcoat.
    pub(crate) blockers: Vec<PatchBlocker>,
}

/// Adds the sources that Topcoat needs. It never removes a source.
pub(crate) fn patch(policy: &str) -> Patched {
    let mut policies = parse(policy);
    if policies.is_empty() {
        return Patched {
            policy: policy.to_owned(),
            blockers: Vec::new(),
        };
    }
    let mut blockers = Vec::new();
    for policy in &mut policies {
        for blocker in policy.blockers() {
            if !blockers.contains(&blocker) {
                blockers.push(blocker);
            }
        }
        policy.patch();
    }
    let rendered: Vec<String> = policies.iter().map(Policy::render).collect();
    Patched {
        policy: rendered.join(", "),
        blockers,
    }
}

/// Returns the policy that Autumn puts on responses for this config.
///
/// This copies the private resolution of autumn-web 0.7:
///
/// - The nonce template replaces the default policy when nonces are on.
/// - Autumn sends no header for a policy that is not a valid header value.
pub(crate) fn effective_policy(headers: &HeadersConfig) -> String {
    if headers.csp_nonce.enabled
        && headers.content_security_policy
            == autumn_web::security::default_content_security_policy()
    {
        AUTUMN_NONCE_TEMPLATE.to_owned()
    } else if http::HeaderValue::from_str(&headers.content_security_policy).is_ok() {
        headers.content_security_policy.clone()
    } else {
        String::new()
    }
}

/// One directive: a lowercase name and its sources.
#[derive(Debug, Clone)]
struct Directive {
    name: String,
    sources: Vec<String>,
}

/// One policy: its directives in order.
#[derive(Debug, Clone)]
struct Policy {
    directives: Vec<Directive>,
}

/// Parses a header value into its policies. The parser drops policies with no
/// directive.
fn parse(text: &str) -> Vec<Policy> {
    text.split(',')
        .map(|policy| Policy {
            directives: policy
                .split(';')
                .filter_map(|directive| {
                    let mut tokens = directive.split_ascii_whitespace();
                    let name = tokens.next()?.to_ascii_lowercase();
                    Some(Directive {
                        name,
                        sources: tokens.map(str::to_owned).collect(),
                    })
                })
                .collect(),
        })
        .filter(|policy| !policy.directives.is_empty())
        .collect()
}

/// Returns `true` if `sources` has the keyword `keyword` (ASCII case-insensitive).
fn has(sources: &[String], keyword: &str) -> bool {
    sources
        .iter()
        .any(|source| source.eq_ignore_ascii_case(keyword))
}

/// Returns `true` if `source` is a nonce or a hash source.
fn is_nonce_or_hash(source: &str) -> bool {
    let lower = source.to_ascii_lowercase();
    ["'nonce-", "'sha256-", "'sha384-", "'sha512-"]
        .iter()
        .any(|prefix| lower.starts_with(prefix))
}

/// Returns `true` if `sources` can permit a same-origin load.
fn permits_same_origin(sources: &[String]) -> bool {
    sources.iter().any(|source| {
        if source.eq_ignore_ascii_case("'self'") || source == "*" {
            return true;
        }
        if source.starts_with('\'') || is_unquoted_keyword(source) {
            return false;
        }
        if let Some(scheme) = source.strip_suffix(':') {
            return scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
        }
        true
    })
}

/// Returns `true` if `source` is a keyword without its quotes, for example
/// `self`. Browsers read it as a host, so it does not permit the app origin.
fn is_unquoted_keyword(source: &str) -> bool {
    const KEYWORDS: [&str; 7] = [
        "self",
        "none",
        "unsafe-inline",
        "unsafe-eval",
        "strict-dynamic",
        "report-sample",
        "wasm-unsafe-eval",
    ];
    KEYWORDS
        .iter()
        .any(|keyword| source.eq_ignore_ascii_case(keyword))
}

impl Policy {
    fn index(&self, name: &str) -> Option<usize> {
        self.directives.iter().position(|d| d.name == name)
    }

    fn get(&self, name: &str) -> Option<&[String]> {
        self.index(name)
            .map(|i| self.directives[i].sources.as_slice())
    }

    fn script(&self) -> Option<&[String]> {
        self.get("script-src").or_else(|| self.get("default-src"))
    }

    fn element(&self) -> Option<&[String]> {
        self.get("script-src-elem").or_else(|| self.script())
    }

    fn connect(&self) -> Option<&[String]> {
        self.get("connect-src").or_else(|| self.get("default-src"))
    }

    fn findings(&self) -> Vec<CspFinding> {
        let mut out = Vec::new();
        if self
            .script()
            .is_some_and(|list| !has(list, "'unsafe-eval'"))
        {
            out.push(CspFinding::EvalBlocked);
        }
        if self
            .get("require-trusted-types-for")
            .is_some_and(|list| has(list, "'script'"))
        {
            out.push(CspFinding::TrustedTypesBlockEval);
        }
        if let Some(list) = self.element() {
            let strict_dynamic = has(list, "'strict-dynamic'");
            let reason = if strict_dynamic {
                Some(InlineBlock::NeutralizedByStrictDynamic)
            } else if list.iter().any(|source| is_nonce_or_hash(source)) {
                Some(InlineBlock::NeutralizedByNonceOrHash)
            } else if has(list, "'unsafe-inline'") {
                None
            } else {
                Some(InlineBlock::MissingUnsafeInline)
            };
            if let Some(reason) = reason {
                out.push(CspFinding::InlineBlocked(reason));
            }
            if strict_dynamic || !permits_same_origin(list) {
                out.push(CspFinding::ModuleBlocked);
            }
        }
        if self
            .connect()
            .is_some_and(|list| !permits_same_origin(list))
        {
            out.push(CspFinding::ConnectBlocked);
        }
        if let Some(flags) = self.get("sandbox") {
            if !has(flags, "allow-scripts") {
                out.push(CspFinding::SandboxBlocksScripts);
            }
            if !has(flags, "allow-same-origin") {
                out.push(CspFinding::SandboxOpaqueOrigin);
            }
        }
        out
    }

    fn blockers(&self) -> Vec<PatchBlocker> {
        let mut out = Vec::new();
        if self
            .element()
            .is_some_and(|list| has(list, "'strict-dynamic'"))
        {
            out.push(PatchBlocker::StrictDynamic);
        }
        if self
            .element()
            .is_some_and(|list| list.iter().any(|source| is_nonce_or_hash(source)))
        {
            out.push(PatchBlocker::NonceOrHash);
        }
        if self
            .get("require-trusted-types-for")
            .is_some_and(|list| has(list, "'script'"))
        {
            out.push(PatchBlocker::TrustedTypes);
        }
        if self
            .get("sandbox")
            .is_some_and(|flags| !has(flags, "allow-scripts") || !has(flags, "allow-same-origin"))
        {
            out.push(PatchBlocker::Sandbox);
        }
        out
    }

    /// Adds a `script-src` with the `default-src` sources, without `'none'`.
    /// Returns its index, or `None` when there is no `default-src`.
    fn copy_default_to_script_src(&mut self) -> Option<usize> {
        let sources: Vec<String> = self
            .get("default-src")?
            .iter()
            .filter(|s| !s.eq_ignore_ascii_case("'none'"))
            .cloned()
            .collect();
        self.directives.push(Directive {
            name: "script-src".to_owned(),
            sources,
        });
        Some(self.directives.len() - 1)
    }

    /// Adds the missing sources. It never removes a source.
    fn patch(&mut self) {
        let has_element = self.index("script-src-elem").is_some();
        let script = self
            .index("script-src")
            .or_else(|| self.copy_default_to_script_src());
        if let Some(index) = script {
            let sources = &mut self.directives[index].sources;
            if !has_element {
                ensure_element_sources(sources);
            }
            ensure(sources, "'unsafe-eval'");
        }
        if let Some(index) = self.index("script-src-elem") {
            ensure_element_sources(&mut self.directives[index].sources);
        }
        match self.index("connect-src") {
            Some(index) => {
                let sources = &mut self.directives[index].sources;
                if !permits_same_origin(sources) {
                    sources.push("'self'".to_owned());
                }
            }
            None => {
                if self
                    .get("default-src")
                    .is_some_and(|d| !permits_same_origin(d))
                {
                    self.directives.push(Directive {
                        name: "connect-src".to_owned(),
                        sources: vec!["'self'".to_owned()],
                    });
                }
            }
        }
    }

    fn render(&self) -> String {
        let parts: Vec<String> = self
            .directives
            .iter()
            .map(|d| {
                if d.sources.is_empty() {
                    d.name.clone()
                } else {
                    format!("{} {}", d.name, d.sources.join(" "))
                }
            })
            .collect();
        parts.join("; ")
    }
}

/// Adds `keyword` when it is missing.
fn ensure(sources: &mut Vec<String>, keyword: &str) {
    if !has(sources, keyword) {
        sources.push(keyword.to_owned());
    }
}

/// Adds the sources that script elements need: same-origin and inline.
fn ensure_element_sources(sources: &mut Vec<String>) {
    if !permits_same_origin(sources) {
        sources.push("'self'".to_owned());
    }
    ensure(sources, "'unsafe-inline'");
}

#[cfg(test)]
mod tests;
