//! Tests for the `csp` module.

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
        findings("script-src https: 'unsafe-eval' 'unsafe-inline'; connect-src app.example.com"),
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

/// Regression: `sandbox` blocks scripts or makes an opaque origin.
#[test]
fn sandbox_is_analyzed() {
    let ok = "script-src 'self' 'unsafe-eval' 'unsafe-inline'";
    assert_eq!(
        findings(&format!("{ok}; sandbox allow-forms")),
        vec![
            CspFinding::SandboxBlocksScripts,
            CspFinding::SandboxOpaqueOrigin
        ]
    );
    assert_eq!(
        findings(&format!("{ok}; sandbox allow-scripts")),
        vec![CspFinding::SandboxOpaqueOrigin]
    );
    assert_eq!(
        findings(&format!("{ok}; sandbox Allow-Scripts allow-same-origin")),
        vec![]
    );
    let patched = patch(&format!("{ok}; sandbox"));
    assert_eq!(patched.blockers, vec![PatchBlocker::Sandbox]);
}

/// Regression: an unquoted keyword is not a host source.
#[test]
fn unquoted_keywords_are_not_host_sources() {
    let policy = "script-src self unsafe-inline unsafe-eval; connect-src self";
    let report = findings(policy);
    assert!(report.contains(&CspFinding::ModuleBlocked), "{report:?}");
    assert!(report.contains(&CspFinding::ConnectBlocked), "{report:?}");
    let patched = patch(policy);
    assert!(patched.blockers.is_empty());
    assert!(analyze(&patched.policy).is_clean(), "{}", patched.policy);
}

/// Regression: `'strict-dynamic'` in `script-src` does not block the patch
/// when `script-src-elem` governs script elements.
#[test]
fn strict_dynamic_in_script_src_does_not_block_with_script_src_elem() {
    let policy =
        "script-src 'self' 'strict-dynamic' 'nonce-x'; script-src-elem 'self' 'unsafe-inline'";
    let patched = patch(policy);
    assert!(patched.blockers.is_empty(), "{:?}", patched.blockers);
    assert!(analyze(&patched.policy).is_clean(), "{}", patched.policy);
}

/// Wildcard and scheme sources.
#[test]
fn wildcard_and_scheme_sources() {
    assert_eq!(
        findings("script-src * 'unsafe-eval' 'unsafe-inline'"),
        vec![]
    );
    assert_eq!(
        findings("default-src * 'unsafe-eval' 'unsafe-inline'"),
        vec![]
    );
    assert_eq!(
        findings("script-src data: 'unsafe-eval' 'unsafe-inline'"),
        vec![CspFinding::ModuleBlocked]
    );
    assert_eq!(
        findings("connect-src wss:"),
        vec![CspFinding::ConnectBlocked]
    );
}

#[test]
fn eval_text_names_both_directives() {
    assert!(CspFinding::EvalBlocked.to_string().contains("default-src"));
}

/// Regression: Autumn drops a policy that is not a valid header value.
#[test]
fn effective_policy_drops_an_invalid_header_value() {
    let headers = HeadersConfig {
        content_security_policy: "default-src 'self';\nscript-src 'self'".into(),
        ..HeadersConfig::default()
    };
    assert_eq!(effective_policy(&headers), "");
}

#[test]
fn patch_fixes_default_and_reports_blockers() {
    let patched = patch(&default_content_security_policy());
    assert!(patched.blockers.is_empty());
    assert_eq!(patched.policy, recommended_csp());

    let blocked =
        patch("script-src 'self' 'strict-dynamic' 'nonce-x'; require-trusted-types-for 'script'");
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
