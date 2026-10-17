//! The spam fixtures are generated here from a fixed seed: benign word lists,
//! not real mail. They prove the classifier learns and generalises; they are
//! not a measure of real-world accuracy.
use currawong_classify::{
    message::MessageView,
    spam::{Bayes, Feedback, RuleSet, SpamClassifier, BAYES_POINTS},
};

const COMMON: &[&str] = &[
    "the",
    "and",
    "for",
    "with",
    "this",
    "that",
    "you",
    "your",
    "please",
    "today",
    "week",
    "about",
    "from",
    "have",
    "will",
    "here",
    "more",
    "information",
    "update",
    "regards",
    "thanks",
    "team",
    "time",
    "new",
    "next",
    "order",
    "review",
    "document",
];
const SPAMMY: &[&str] = &[
    "offer",
    "discount",
    "casino",
    "bonus",
    "guaranteed",
    "cheap",
    "loan",
    "approved",
    "credit",
    "winner",
    "exclusive",
    "deal",
    "save",
    "limited",
    "pills",
    "crypto",
    "investment",
    "returns",
    "unsubscribe",
    "click",
    "cash",
    "prize",
    "free",
    "shipping",
    "luxury",
    "replica",
    "lottery",
    "jackpot",
    "miracle",
    "selected",
];
const HAMMY: &[&str] = &[
    "meeting",
    "agenda",
    "roster",
    "minutes",
    "quarterly",
    "project",
    "draft",
    "report",
    "lunch",
    "budget",
    "schedule",
    "client",
    "contract",
    "timesheet",
    "handover",
    "deadline",
    "workshop",
    "training",
    "policy",
    "feedback",
    "presentation",
    "proposal",
    "milestone",
    "sprint",
    "standup",
    "leave",
    "approval",
    "spreadsheet",
    "invoice",
    "board",
];

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    fn chance(&mut self, percent: usize) -> bool {
        self.below(100) < percent
    }
    fn pick<'a>(&mut self, words: &[&'a str]) -> &'a str {
        words[self.below(words.len())]
    }
}

fn fixture(rng: &mut Rng, spam: bool) -> Vec<u8> {
    let (own, other) = if spam {
        (SPAMMY, HAMMY)
    } else {
        (HAMMY, SPAMMY)
    };
    let word = |rng: &mut Rng| {
        let roll = rng.below(100);
        if roll < 55 {
            rng.pick(COMMON)
        } else if roll < 88 {
            rng.pick(own)
        } else {
            rng.pick(other)
        }
    };
    let subject: Vec<&str> = (0..3 + rng.below(4)).map(|_| word(rng)).collect();
    let body: Vec<&str> = (0..40 + rng.below(40)).map(|_| word(rng)).collect();
    let sender = match (spam, rng.chance(30)) {
        (_, true) => format!("user{}@mail.example", rng.below(50)),
        (true, false) => format!("news@promo{}.example", rng.below(40)),
        (false, false) => format!("staff{}@example.test", rng.below(20)),
    };
    format!(
        "From: {sender}\r\nTo: team@example.test\r\nSubject: {}\r\n\r\n{}\r\n",
        subject.join(" "),
        body.join(" ")
    )
    .into_bytes()
}

fn classifier(bayes: Option<Bayes>) -> SpamClassifier {
    SpamClassifier {
        bayes,
        rules: RuleSet::builtin().unwrap(),
    }
}

#[test]
fn spam_bayes_held_out_accuracy_is_over_ninety_percent() {
    let dir = tempfile::tempdir().unwrap();
    let spam = classifier(Some(Bayes::open(&dir.path().join("bayes.sqlite")).unwrap()));
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    for i in 0..200 {
        let id = format!("spam-{i}");
        spam.learn(
            "tenant-a",
            &id,
            &fixture(&mut rng, true),
            Feedback::ReportedSpam,
        )
        .unwrap();
        let id = format!("ham-{i}");
        spam.learn(
            "tenant-a",
            &id,
            &fixture(&mut rng, false),
            Feedback::Released,
        )
        .unwrap();
    }
    let mut held_out = Rng(0x0dd_ba11_cafe_f00d);
    let mut correct = 0;
    let total = 200;
    for i in 0..total {
        let is_spam = i % 2 == 0;
        let raw = fixture(&mut held_out, is_spam);
        let report = spam.score("tenant-a", &MessageView::parse(&raw), &[]);
        if (report.bayes >= 0.5) == is_spam {
            correct += 1;
        }
    }
    let accuracy = correct as f64 / total as f64;
    eprintln!("held-out accuracy {accuracy}");
    assert!(accuracy > 0.9, "held-out accuracy {accuracy}");

    // Another tenant has not trained, so its Bayes score stays neutral.
    let raw = fixture(&mut held_out, true);
    let other = spam.score("tenant-b", &MessageView::parse(&raw), &[]);
    assert_eq!(other.bayes, 0.5);
}

#[test]
fn spam_rule_hits_appear_in_the_report() {
    let spam = classifier(None);
    let raw = b"From: a@promo.example\r\nSubject: WINNER WINNER\r\nX-Mailer: BulkMail Pro\r\n\r\nAct now, see http://192.0.2.10/claim today.\r\n";
    let report = spam.score(
        "tenant-a",
        &MessageView::parse(raw),
        &["https://bit.ly/abc".to_string()],
    );
    let names: Vec<&str> = report
        .rules_hit
        .iter()
        .map(|hit| hit.name.as_str())
        .collect();
    for expected in [
        "subject_shouting",
        "subject_prize",
        "body_urgency",
        "uri_ip_literal",
        "uri_shortener",
        "header_bulk_mailer",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} missing from {names:?}"
        );
    }
    assert_eq!(report.bayes, 0.5);
    let rules: f64 = report.rules_hit.iter().map(|hit| hit.score).sum();
    assert!((report.total - rules).abs() < 1e-9);

    let clean = spam.score(
        "tenant-a",
        &MessageView::parse(b"From: a@example.test\r\nSubject: Roster for next week\r\n\r\nSee the attached roster.\r\n"),
        &[],
    );
    assert!(clean.rules_hit.is_empty(), "{:?}", clean.rules_hit);
    assert_eq!(clean.total, 0.0);
}

#[test]
fn spam_rules_load_from_a_directory_and_bayes_adds_points() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(
        dir.path().join("10-local.toml"),
        "[[rule]]\nname = \"local_invoice_lure\"\ntarget = \"header:subject\"\npattern = \"(?i)overdue invoice\"\nscore = 2.5\n\n[[rule]]\nname = \"local_newsletter_allow\"\ntarget = \"header:List-Id\"\npattern = \"news\\\\.example\\\\.test\"\nscore = -1.0\n",
    )
    .unwrap();
    std::fs::write(dir.path().join("README.md"), "not a rule file").unwrap();
    let rules = RuleSet::load_dir(dir.path()).unwrap();
    assert_eq!(rules.len(), 2);
    let repo = RuleSet::load_dir(
        &std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../rules/spam"),
    )
    .unwrap();
    assert_eq!(repo.len(), RuleSet::builtin().unwrap().len());

    let bayes = Bayes::in_memory().unwrap();
    let spam = SpamClassifier {
        bayes: Some(bayes),
        rules,
    };
    let lure = b"From: a@example.test\r\nSubject: Overdue invoice\r\nList-Id: <news.example.test>\r\n\r\nPay now\r\n";
    spam.learn("t", "m1", lure, Feedback::ReportedSpam).unwrap();
    spam.learn(
        "t",
        "m2",
        b"From: b@example.test\r\nSubject: Lunch\r\n\r\nSandwiches at noon\r\n",
        Feedback::ReportedHam,
    )
    .unwrap();
    let report = spam.score("t", &MessageView::parse(lure), &[]);
    let names: Vec<&str> = report
        .rules_hit
        .iter()
        .map(|hit| hit.name.as_str())
        .collect();
    assert_eq!(names, vec!["local_invoice_lure", "local_newsletter_allow"]);
    assert!(report.bayes > 0.5, "{}", report.bayes);
    let expected = (report.bayes - 0.5) * 2.0 * BAYES_POINTS + 1.5;
    assert!((report.total - expected).abs() < 1e-9, "{report:?}");
}

#[test]
fn spam_learning_without_a_store_is_an_error() {
    let err = classifier(None)
        .learn("t", "m", b"Subject: x\r\n\r\ny\r\n", Feedback::Released)
        .unwrap_err();
    assert!(err.to_string().contains("not open"), "{err}");
}

#[test]
fn spam_padding_with_unknown_words_does_not_neutralise_bayes() {
    let spam = classifier(Some(Bayes::in_memory().unwrap()));
    let mut rng = Rng(0x5eed_1234_abcd_0001);
    for i in 0..50 {
        spam.learn(
            "t",
            &format!("s{i}"),
            &fixture(&mut rng, true),
            Feedback::ReportedSpam,
        )
        .unwrap();
        spam.learn(
            "t",
            &format!("h{i}"),
            &fixture(&mut rng, false),
            Feedback::Released,
        )
        .unwrap();
    }
    let raw = String::from_utf8(fixture(&mut rng, true)).unwrap();
    let plain = spam.score("t", &MessageView::parse(raw.as_bytes()), &[]);
    assert!(plain.bayes > 0.9, "{}", plain.bayes);
    // 2,500 never-seen words that sort before every real token.
    let padding: Vec<String> = (1..=2500).map(|i| format!("aaa{i:05}")).collect();
    let padded = format!("{raw}\r\n{}\r\n", padding.join(" "));
    let report = spam.score("t", &MessageView::parse(padded.as_bytes()), &[]);
    assert!(
        report.bayes > 0.9,
        "padding diluted Bayes to {}",
        report.bayes
    );
}

#[test]
fn spam_long_bodies_keep_header_sender_and_url_tokens() {
    let words: Vec<String> = (0..3000).map(|i| format!("aaa{i:05}")).collect();
    let raw = format!(
        "From: news@promo.example\r\nSubject: Weekly digest\r\nX-Mailer: Bulk Mail\r\n\r\nhttps://promo.example/x\r\n{}\r\n",
        words.join(" ")
    );
    let tokens = currawong_classify::spam::bayes::tokens(&MessageView::parse(raw.as_bytes()), &[]);
    for expected in [
        "sender:promo.example",
        "subject:digest",
        "x-mailer:bulk",
        "url:promo.example",
        "header:subject",
    ] {
        assert!(tokens.iter().any(|t| t == expected), "{expected} missing");
    }
}

#[test]
fn spam_rules_see_encoded_subjects() {
    let spam = classifier(None);
    // "You have won a prize", base64 encoded.
    let raw = b"From: a@promo.example\r\nSubject: =?utf-8?b?WW91IGhhdmUgd29uIGEgcHJpemU=?=\r\n\r\nhello\r\n";
    let report = spam.score("t", &MessageView::parse(raw), &[]);
    let names: Vec<&str> = report
        .rules_hit
        .iter()
        .map(|hit| hit.name.as_str())
        .collect();
    assert_eq!(names, vec!["subject_prize"]);
}

#[test]
fn spam_degraded_scoring_is_noted() {
    let classifier = currawong_classify::Classifier::new(&[], classifier(None));
    let result = classifier.classify(
        &currawong_classify::TenantContext::domain("example.test"),
        b"From: a@example.test\r\nSubject: hi\r\n\r\nhello\r\n",
        "",
        &[],
    );
    assert_eq!(result.spam.unwrap().bayes, 0.5);
    assert!(
        result
            .notes
            .iter()
            .any(|note| note.contains("bayes store unavailable")),
        "{:?}",
        result.notes
    );
}
