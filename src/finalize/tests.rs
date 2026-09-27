//! Tests for the `finalize` module.

use super::*;

#[test]
fn panic_text_reads_str_and_string_payloads() {
    let text: Box<dyn Any + Send> = Box::new("static");
    assert_eq!(panic_text(text.as_ref()), "static");
    let owned: Box<dyn Any + Send> = Box::new(String::from("owned"));
    assert_eq!(panic_text(owned.as_ref()), "owned");
    let other: Box<dyn Any + Send> = Box::new(7_u8);
    assert_eq!(panic_text(other.as_ref()), "a panic with no text");
}

#[test]
fn invalid_token_header_falls_back_like_autumn() {
    let mut config = AutumnConfig::default();
    config.security.csrf.enabled = true;
    config.security.csrf.token_header = "bad header".into();
    let settings = ingress_settings(&config).unwrap();
    assert_eq!(settings.token_header.as_str(), DEFAULT_TOKEN_HEADER);
    config.security.csrf.enabled = false;
    assert!(ingress_settings(&config).is_none());
}

#[test]
fn blocker_advice_names_each_blocker() {
    let advice = blocker_advice(&[PatchBlocker::StrictDynamic, PatchBlocker::TrustedTypes]);
    assert!(advice.contains("'strict-dynamic'"));
    assert!(advice.contains("require-trusted-types-for"));
}
