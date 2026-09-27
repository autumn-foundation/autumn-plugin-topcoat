//! Content-Security-Policy analysis for Topcoat.
//!
//! Autumn sets the `Content-Security-Policy` header on each response. The
//! Topcoat runtime needs three things from that policy:
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
//! - `analyze` never panics. An empty or blank policy is disabled and has no
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
//! - A list permits same-origin loads if it has `'self'`, `*`, a host source
//!   or a scheme source.
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
    /// `script-src` has no `'unsafe-eval'`. The runtime cannot compile expressions.
    EvalBlocked,
    /// `require-trusted-types-for 'script'` blocks `new Function`.
    TrustedTypesBlockEval,
    /// Inline scripts are blocked. Streamed swaps and redirects do not run.
    InlineBlocked(InlineBlock),
    /// The runtime module from `/_topcoat/assets` cannot load.
    ModuleBlocked,
    /// The runtime cannot connect to the server.
    ConnectBlocked,
}

/// Why inline scripts are blocked.
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
    /// Returns `true` if the policy does not block Topcoat.
    #[must_use]
    pub const fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

impl std::fmt::Display for CspFinding {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let text = match self {
            Self::EvalBlocked => "script-src has no 'unsafe-eval'",
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
            Self::ModuleBlocked => "same-origin module scripts are blocked",
            Self::ConnectBlocked => "connect-src blocks same-origin connections",
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
/// This copies the private resolution of autumn-web 0.7: the nonce template
/// replaces the default policy when nonces are on.
pub(crate) fn effective_policy(headers: &HeadersConfig) -> String {
    if headers.csp_nonce.enabled
        && headers.content_security_policy
            == autumn_web::security::default_content_security_policy()
    {
        AUTUMN_NONCE_TEMPLATE.to_owned()
    } else {
        headers.content_security_policy.clone()
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

/// Parses a header value into its policies. Policies with no directive are dropped.
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
        if source.starts_with('\'') {
            return false;
        }
        if let Some(scheme) = source.strip_suffix(':') {
            return scheme.eq_ignore_ascii_case("http") || scheme.eq_ignore_ascii_case("https");
        }
        true
    })
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
        out
    }

    fn blockers(&self) -> Vec<PatchBlocker> {
        let mut out = Vec::new();
        let strict = |list: Option<&[String]>| list.is_some_and(|l| has(l, "'strict-dynamic'"));
        if strict(self.element()) || strict(self.script()) {
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
mod tests {
    use super::*;
    use autumn_web::security::default_content_security_policy;
    use proptest::prelude::*;

    fn findings(policy: &str) -> Vec<CspFinding> {
        analyze(policy).findings
    }

    // ---------- regression pins ----------

    #[test]
    fn autumn_default_blocks_eval_and_inline() {
        assert_eq!(
            findings(&default_content_security_policy()),
            vec![
                CspFinding::EvalBlocked,
                CspFinding::InlineBlocked(InlineBlock::MissingUnsafeInline)
            ]
        );
    }

    #[test]
    fn nonce_template_neutralizes_inline() {
        assert_eq!(
            findings(AUTUMN_NONCE_TEMPLATE),
            vec![
                CspFinding::EvalBlocked,
                CspFinding::InlineBlocked(InlineBlock::NeutralizedByNonceOrHash)
            ]
        );
    }

    #[test]
    fn empty_policy_is_disabled() {
        for empty in ["", "   ", " , "] {
            let report = analyze(empty);
            assert!(report.disabled, "{empty:?}");
            assert!(report.is_clean());
        }
    }

    #[test]
    fn recommended_policy_is_exact_and_clean() {
        assert_eq!(
            recommended_csp(),
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; \
             script-src 'self' 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; \
             form-action 'self'; frame-ancestors 'none'; base-uri 'self'"
        );
        assert!(analyze(&recommended_csp()).is_clean());
    }

    // ---------- examples ----------

    #[test]
    fn fallback_chains() {
        assert_eq!(
            findings("default-src 'self' 'unsafe-eval' 'unsafe-inline'"),
            vec![]
        );
        assert_eq!(
            findings("img-src 'self'"),
            vec![],
            "no script or default list"
        );
        assert_eq!(
            findings("script-src 'self' 'unsafe-eval'; script-src-elem 'self'"),
            vec![CspFinding::InlineBlocked(InlineBlock::MissingUnsafeInline)]
        );
        assert_eq!(
            findings("default-src 'none'; script-src 'self' 'unsafe-eval' 'unsafe-inline'"),
            vec![CspFinding::ConnectBlocked]
        );
    }

    #[test]
    fn neutralization_order() {
        assert_eq!(
            findings("script-src 'self' 'unsafe-eval' 'unsafe-inline' 'strict-dynamic' 'nonce-a'"),
            vec![
                CspFinding::InlineBlocked(InlineBlock::NeutralizedByStrictDynamic),
                CspFinding::ModuleBlocked
            ]
        );
        assert_eq!(
            findings("script-src 'self' 'unsafe-eval' 'unsafe-inline' 'sha256-abc'"),
            vec![CspFinding::InlineBlocked(
                InlineBlock::NeutralizedByNonceOrHash
            )]
        );
    }

    #[test]
    fn host_and_scheme_sources_permit_same_origin() {
        assert_eq!(
            findings(
                "script-src https: 'unsafe-eval' 'unsafe-inline'; connect-src app.example.com"
            ),
            vec![]
        );
        assert_eq!(
            findings("script-src 'unsafe-eval' 'unsafe-inline'"),
            vec![CspFinding::ModuleBlocked]
        );
    }

    #[test]
    fn trusted_types_and_case() {
        assert_eq!(
            findings(
                "SCRIPT-SRC 'SELF' 'UNSAFE-EVAL' 'UNSAFE-INLINE'; Require-Trusted-Types-For 'script'"
            ),
            vec![CspFinding::TrustedTypesBlockEval]
        );
        assert_eq!(
            findings("script-src 'self' 'wasm-unsafe-eval' 'unsafe-inline'"),
            vec![CspFinding::EvalBlocked]
        );
    }

    #[test]
    fn first_directive_wins_and_policies_union() {
        assert_eq!(
            findings("script-src 'self' 'unsafe-eval' 'unsafe-inline'; script-src 'none'"),
            vec![]
        );
        assert_eq!(
            findings("script-src 'self' 'unsafe-eval' 'unsafe-inline', connect-src 'none'"),
            vec![CspFinding::ConnectBlocked]
        );
    }

    #[test]
    fn patch_fixes_default_and_reports_blockers() {
        let patched = patch(&default_content_security_policy());
        assert!(patched.blockers.is_empty());
        assert_eq!(patched.policy, recommended_csp());

        let blocked = patch(
            "script-src 'self' 'strict-dynamic' 'nonce-x'; require-trusted-types-for 'script'",
        );
        assert_eq!(
            blocked.blockers,
            vec![
                PatchBlocker::StrictDynamic,
                PatchBlocker::NonceOrHash,
                PatchBlocker::TrustedTypes
            ]
        );

        assert_eq!(patch("").policy, "");
        let created = patch("default-src 'none'");
        assert!(analyze(&created.policy).is_clean(), "{}", created.policy);
    }

    #[test]
    fn effective_policy_mirrors_autumn() {
        let mut headers = HeadersConfig::default();
        assert_eq!(
            effective_policy(&headers),
            default_content_security_policy()
        );
        headers.csp_nonce.enabled = true;
        assert_eq!(effective_policy(&headers), AUTUMN_NONCE_TEMPLATE);
        headers.content_security_policy = "default-src 'self'".into();
        assert_eq!(effective_policy(&headers), "default-src 'self'");
        headers.content_security_policy = String::new();
        assert_eq!(effective_policy(&headers), "");
    }

    #[test]
    fn findings_have_text() {
        for finding in [
            CspFinding::EvalBlocked,
            CspFinding::TrustedTypesBlockEval,
            CspFinding::InlineBlocked(InlineBlock::NeutralizedByStrictDynamic),
            CspFinding::InlineBlocked(InlineBlock::NeutralizedByNonceOrHash),
            CspFinding::InlineBlocked(InlineBlock::MissingUnsafeInline),
            CspFinding::ModuleBlocked,
            CspFinding::ConnectBlocked,
        ] {
            assert!(!finding.to_string().is_empty());
        }
    }

    // ---------- properties ----------

    fn source() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "'self'",
            "'SELF'",
            "'none'",
            "*",
            "'unsafe-eval'",
            "'unsafe-inline'",
            "'Unsafe-Inline'",
            "'wasm-unsafe-eval'",
            "'strict-dynamic'",
            "'nonce-abc'",
            "'sha256-xyz'",
            "https:",
            "cdn.example.com",
            "data:",
            "'report-sample'",
        ])
        .prop_map(str::to_owned)
    }

    fn directive() -> impl Strategy<Value = String> {
        (
            prop::sample::select(vec![
                "default-src",
                "script-src",
                "script-src-elem",
                "connect-src",
                "img-src",
                "style-src",
                "Script-Src",
                "require-trusted-types-for",
                "frame-ancestors",
            ]),
            prop::collection::vec(source(), 0..4),
        )
            .prop_map(|(name, sources)| format!("{name} {}", sources.join(" ")))
    }

    fn policy() -> impl Strategy<Value = String> {
        prop::collection::vec(directive(), 0..6).prop_map(|d| d.join("; "))
    }

    fn non_empty_policy() -> impl Strategy<Value = String> {
        prop::collection::vec(directive(), 1..6).prop_map(|d| d.join("; "))
    }

    proptest! {
        #[test]
        fn analyze_and_patch_are_total(s in any::<String>()) {
            let _ = analyze(&s);
            let _ = patch(&s);
        }

        #[test]
        fn unrelated_directives_do_not_change_findings(p in policy(), extra in prop::sample::select(vec!["img-src 'none'", "style-src 'none'", "frame-ancestors 'none'", "base-uri 'none'", "report-uri /r"])) {
            let with = if p.is_empty() { extra.to_owned() } else { format!("{p}; {extra}") };
            let a = analyze(&p);
            let b = analyze(&with);
            prop_assert_eq!(a.findings, b.findings);
        }

        #[test]
        fn comma_joined_policies_union(p in non_empty_policy(), q in non_empty_policy()) {
            let joined = analyze(&format!("{p}, {q}"));
            let mut expected = analyze(&p).findings;
            for finding in analyze(&q).findings {
                if !expected.contains(&finding) {
                    expected.push(finding);
                }
            }
            let mut got = joined.findings;
            got.sort_by_key(|f| format!("{f:?}"));
            expected.sort_by_key(|f| format!("{f:?}"));
            prop_assert_eq!(got, expected);
        }

        #[test]
        fn patch_is_clean_idempotent_and_additive(p in policy()) {
            let patched = patch(&p);
            if patched.blockers.is_empty() {
                prop_assert!(analyze(&patched.policy).is_clean(), "not clean: {}", patched.policy);
            }
            prop_assert_eq!(&patch(&patched.policy).policy, &patched.policy);
            let before: Vec<String> = p.split([';', ',']).flat_map(|d| d.split_whitespace().skip(1).map(str::to_ascii_lowercase).collect::<Vec<_>>()).collect();
            let after = patched.policy.to_ascii_lowercase();
            for token in before {
                prop_assert!(after.contains(&token), "lost {} in {}", token, patched.policy);
            }
        }

        #[test]
        fn analysis_is_case_insensitive(p in policy()) {
            prop_assert_eq!(analyze(&p), analyze(&p.to_ascii_uppercase()));
            prop_assert_eq!(analyze(&p), analyze(&p.to_ascii_lowercase()));
        }
    }
}
