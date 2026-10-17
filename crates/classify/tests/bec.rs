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

fn message(headers: &str, body: &str) -> Vec<u8> {
    format!("{headers}\r\nTo: ap@acme.test\r\nSubject: hello\r\n\r\n{body}\r\n").into_bytes()
}

fn reasons(raw: &[u8]) -> (f64, Vec<BecReason>) {
    let bec = classifier()
        .classify_with(&tenant(), raw, "", &[], inbound())
        .bec
        .unwrap();
    (bec.score, bec.reasons)
}

#[test]
fn bec_padding_cannot_push_the_request_out_of_view() {
    let body = format!(
        "{}\r\nPlease buy gift cards urgently and keep this confidential.",
        "filler ".repeat(12_000)
    );
    let (_, found) = reasons(&message("From: \"Jane Smith\" <js@gmail.com>", &body));
    assert!(found.contains(&BecReason::GiftCard), "{found:?}");
    assert!(found.contains(&BecReason::Secrecy), "{found:?}");
}

#[test]
fn bec_wrapped_spaced_and_disguised_phrases_still_match() {
    for body in [
        "Our new bank\r\ndetails are below. BSB: 000-000 Account: 00000000",
        "Our new bank  details: BSB number 000000 acc 0000 0000",
        "Our new b\u{0430}nk details: BSB 000 000 account number 00000000",
    ] {
        let (_, found) = reasons(&message("From: Supplier <billing@vendor.test>", body));
        assert!(
            found.contains(&BecReason::PaymentChange),
            "{body}: {found:?}"
        );
    }
    let (_, found) = reasons(&message(
        "From: x <x@vendor.test>",
        "Grab some Gift-Cards for the team",
    ));
    assert!(found.contains(&BecReason::GiftCard), "{found:?}");
}

#[test]
fn bec_ordinary_invoices_are_not_payment_changes() {
    // A first-time supplier quoting its normal bank details on an invoice.
    let raw = message(
        "From: Bob's Plumbing via Xero <messaging-service@post.xero.test>\r\nReply-To: bobsplumbing@bigpond.com",
        "Invoice INV-0042 is attached. Pay to BSB 000-000, Account number 00000000. Please pay as soon as possible. Remittance advice to this address.",
    );
    let (score, found) = reasons(&raw);
    assert!(!found.contains(&BecReason::PaymentChange), "{found:?}");
    assert!(score < THRESHOLD, "{score} {found:?}");
}

#[test]
fn bec_a_known_supplier_changing_bank_details_is_held() {
    // A compromised but known mailbox, no Reply-To, DMARC passing.
    let classifier = classifier();
    let tenant = tenant();
    classifier.record_delivery(&tenant, "accounts@supplier.test", &["ap@acme.test".into()]);
    let raw = message(
        "From: Accounts <accounts@supplier.test>",
        "Please note our bank details have changed. New BSB: 000-000 Account number: 00000000",
    );
    let bec = classifier
        .classify_with(&tenant, &raw, "", &[], inbound())
        .bec
        .unwrap();
    assert!(bec.score >= THRESHOLD, "{bec:?}");
    assert!(!bec.reasons.contains(&BecReason::FirstTimeSender));
}

#[test]
fn bec_reply_to_differences_are_weighed() {
    let (_, found) = reasons(&message(
        "From: Sales <sales@vendor.test>\r\nReply-To: sales@vendor-replies.test",
        "hello",
    ));
    assert!(found.contains(&BecReason::ReplyToMismatch), "{found:?}");
    let (_, found) = reasons(&message(
        "From: Sales <sales@vendor.test>\r\nReply-To: Sales <SALES@vendor.test>",
        "hello",
    ));
    assert!(!found.contains(&BecReason::ReplyToMismatch), "{found:?}");
    let (_, found) = reasons(&message(
        "From: Me <me.one@gmail.com>\r\nReply-To: me.two@gmail.com",
        "hello",
    ));
    assert!(found.contains(&BecReason::ReplyToMismatch), "{found:?}");
}

#[test]
fn bec_vip_spoof_alone_reaches_the_threshold_and_staff_subdomains_are_internal() {
    let (score, found) = reasons(&message(
        "From: \"Jane Smith - CEO\" <js.office@gmail.com>",
        "Are you free?",
    ));
    assert!(found.contains(&BecReason::DisplayNameSpoof));
    assert!(score >= THRESHOLD, "{score}");
    let (_, found) = reasons(&message(
        "From: Jane Smith <jane@mail.acme.test>",
        "Are you free?",
    ));
    assert!(!found.contains(&BecReason::DisplayNameSpoof), "{found:?}");
    let (score, _) = reasons(&message("From: x <x@vendor.test>", "nothing to see"));
    assert_eq!(score.to_bits(), 0.0_f64.to_bits(), "no negative zero");
}
