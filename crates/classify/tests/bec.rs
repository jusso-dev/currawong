use currawong_classify::bec::{BecContext, SenderHistory};
use currawong_classify::spam::{RuleSet, SpamClassifier};
use currawong_classify::{Classifier, TenantContext};
use currawong_core::directory::CsvDirectory;
use currawong_core::BecReason;
use std::sync::Arc;

/// Default pack threshold for `bec`.
const THRESHOLD: f64 = 0.6;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../../testdata/bec/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn classifier() -> Classifier {
    let directory = CsvDirectory::parse(
        "email,name,vip\njane.smith@acme.test,Jane Smith,true\nap@acme.test,Accounts Payable\n",
    )
    .unwrap();
    let spam = SpamClassifier {
        bayes: None,
        rules: RuleSet::builtin().unwrap(),
    };
    Classifier::new(&[], spam)
        .with_directory(Arc::new(directory))
        .with_history(SenderHistory::in_memory().unwrap())
}

fn tenant() -> TenantContext {
    TenantContext::tenant("acme", &["acme.test".to_string()])
}

fn inbound() -> Option<BecContext> {
    Some(BecContext::default())
}

#[test]
fn bec_ceo_gift_cards_scores_over_threshold_with_display_name_spoof() {
    let result = classifier().classify_with(
        &tenant(),
        &fixture("ceo-gift-cards.eml"),
        "",
        &[],
        inbound(),
    );
    let bec = result.bec.unwrap();
    assert!(bec.score > THRESHOLD, "{bec:?}");
    assert!(
        bec.reasons.contains(&BecReason::DisplayNameSpoof),
        "{bec:?}"
    );
    assert!(bec.reasons.contains(&BecReason::GiftCard), "{bec:?}");
}

#[test]
fn bec_bank_change_gets_payment_change() {
    let result =
        classifier().classify_with(&tenant(), &fixture("bank-change.eml"), "", &[], inbound());
    let bec = result.bec.unwrap();
    assert!(bec.reasons.contains(&BecReason::PaymentChange), "{bec:?}");
    assert!(bec.reasons.contains(&BecReason::ReplyToMismatch), "{bec:?}");
    assert!(bec.reasons.contains(&BecReason::FirstTimeSender), "{bec:?}");
    assert!(bec.score > THRESHOLD, "{bec:?}");
}

#[test]
fn bec_newsletter_scores_under_threshold() {
    let result =
        classifier().classify_with(&tenant(), &fixture("newsletter.eml"), "", &[], inbound());
    let bec = result.bec.unwrap();
    assert!(bec.score < THRESHOLD, "{bec:?}");
    assert!(!bec.reasons.contains(&BecReason::DisplayNameSpoof));
    assert!(!bec.reasons.contains(&BecReason::PaymentChange));
}

#[test]
fn bec_known_sender_is_not_first_time_and_outbound_is_not_scored() {
    let classifier = classifier();
    let tenant = tenant();
    classifier.record_delivery(
        &tenant,
        "accounts@supplier-billing.test",
        &["ap@acme.test".into()],
    );
    let result = classifier.classify_with(&tenant, &fixture("bank-change.eml"), "", &[], inbound());
    assert!(!result
        .bec
        .unwrap()
        .reasons
        .contains(&BecReason::FirstTimeSender));
    // Plain classify (outbound) runs no BEC analysis.
    assert!(classifier
        .classify(&tenant, &fixture("bank-change.eml"), "", &[])
        .bec
        .is_none());
}

#[test]
fn bec_display_name_rules_avoid_false_positives() {
    let classifier = classifier();
    let raw = |from: &str| {
        format!(
            "From: {from}\r\nTo: finance@acme.test\r\nSubject: hello\r\n\r\nSee you at lunch.\r\n"
        )
        .into_bytes()
    };
    let spoof = |from: &str| {
        classifier
            .classify_with(&tenant(), &raw(from), "", &[], inbound())
            .bec
            .unwrap()
            .reasons
            .contains(&BecReason::DisplayNameSpoof)
    };
    // The real Jane, from inside the tenant.
    assert!(!spoof("Jane Smith <jane.smith@acme.test>"));
    // Someone else who happens to share no directory name.
    assert!(!spoof("Janet Smithers <janet@gmail.com>"));
    // Name order and titles do not hide the match.
    assert!(spoof("\"Smith, Jane\" <boss@gmail.com>"));
    // A tenant address written into the display name.
    assert!(spoof("\"bob@acme.test\" <bob.acme@gmail.com>"));
}
