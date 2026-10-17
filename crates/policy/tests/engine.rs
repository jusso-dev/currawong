use currawong_core::{AuthMethodResult, AuthResults, Direction, MessageId, ScanReport, Verdict};
use currawong_policy::{
    decide, default_pack, evaluate, evaluate_signals, Action, Condition, Context, Message, Policy,
    PolicySet, PolicyStore, Scope, Signals,
};

fn report() -> ScanReport {
    ScanReport::new(MessageId("01ARZ3NDEKTSV4RRFFQ69G5FAV".into()))
}

fn ctx(recipient: &str) -> Context<'_> {
    Context {
        tenant_id: Some("t1"),
        direction: Direction::Inbound,
        sender: "someone@sender.test",
        recipient,
    }
}

fn policy(id: &str, scope: Scope, priority: i64, actions: Vec<Action>) -> Policy {
    Policy {
        id: id.into(),
        tenant_id: match scope {
            Scope::Global => None,
            _ => Some("t1".into()),
        },
        scope,
        priority,
        enabled: true,
        dry_run: false,
        conditions: Vec::new(),
        actions,
    }
}

fn spoofed() -> AuthResults {
    let fail = || AuthMethodResult {
        result: "fail".into(),
        detail: String::new(),
    };
    AuthResults {
        spf: fail(),
        dkim: Vec::new(),
        dmarc: fail(),
        arc: AuthMethodResult::none(),
        dmarc_policy: "reject".into(),
        header: String::new(),
    }
}

fn default_verdict(signals: &Signals) -> Verdict {
    evaluate(signals, &ctx("user@example.com.au"), default_pack()).verdict
}

#[test]
fn default_pack_covers_each_signal() {
    let quarantined = |reason: &str, signals: &Signals| {
        assert_eq!(
            default_verdict(signals),
            Verdict::Quarantine {
                reason: reason.into()
            },
            "{signals:?}"
        );
    };
    for (flag, id) in [
        ("malware", "malware"),
        ("active_content", "active-content"),
        ("fail_closed", "scan-failed"),
    ] {
        let mut signals = Signals::default();
        signals.flag(flag);
        quarantined(id, &signals);
    }
    let mut spoof = report();
    spoof.auth = Some(spoofed());
    quarantined("dmarc-reject", &Signals::from_report(&spoof));
    // DMARC fail under p=none is delivered.
    spoof.auth.as_mut().unwrap().dmarc_policy = "none".into();
    assert_eq!(
        default_verdict(&Signals::from_report(&spoof)),
        Verdict::Deliver
    );

    let mut spam = Signals::default();
    spam.score("spam", 9.5);
    quarantined("spam-quarantine", &spam);
    spam.score("spam", 8.0);
    quarantined("spam-quarantine", &spam);
    spam.score("spam", 6.0);
    let tagged = evaluate(&spam, &ctx("user@example.com.au"), default_pack());
    assert_eq!(tagged.verdict, Verdict::Deliver);
    assert_eq!(
        tagged.actions,
        vec![Action::AddHeader {
            name: "X-Currawong-Spam".into(),
            value: "[SPAM]".into()
        }]
    );
    spam.score("spam", 4.9);
    let plain = evaluate(&spam, &ctx("user@example.com.au"), default_pack());
    assert_eq!(plain.verdict, Verdict::Deliver);
    assert!(plain.actions.is_empty());
}

#[test]
fn old_m1_priorities_hold() {
    let mut infected = report();
    infected.malware = true;
    infected.defer = true;
    assert_eq!(
        decide(&infected),
        Verdict::Quarantine {
            reason: "malware".into()
        }
    );
    let mut deferred = report();
    deferred.defer = true;
    deferred.active_content = true;
    assert!(matches!(decide(&deferred), Verdict::Defer { .. }));
    assert_eq!(decide(&report()), Verdict::Deliver);
}

#[test]
fn explanation_lists_every_matched_policy() {
    let mut header = policy(
        "vip-header",
        Scope::User("ceo@example.com.au".into()),
        10,
        vec![Action::AddHeader {
            name: "X-Vip".into(),
            value: "yes".into(),
        }],
    );
    header.conditions.push(Condition::Flag("malware".into()));
    let quarantine = policy(
        "infected",
        Scope::Global,
        10,
        vec![Action::Quarantine("malware".into())],
    );
    let mut trial = policy("trial-reject", Scope::Global, 5, vec![Action::Discard]);
    trial.dry_run = true;
    let set = PolicySet {
        policies: vec![quarantine, trial, header],
        ..Default::default()
    };
    let mut signals = Signals::default();
    signals.flag("malware");
    let decision = evaluate(&signals, &ctx("ceo@example.com.au"), &set);
    let ids: Vec<&str> = decision.matched.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["vip-header", "trial-reject", "infected"]);
    for id in ids {
        assert!(
            decision.explanation.iter().any(|line| line.starts_with(id)),
            "{id} missing from {:?}",
            decision.explanation
        );
    }
    assert!(decision.explanation[1].contains("dry run"));
    assert_eq!(
        decision.verdict,
        Verdict::Quarantine {
            reason: "infected".into()
        }
    );
}

#[test]
fn dry_run_policy_does_not_change_the_verdict() {
    let mut signals = Signals::default();
    signals.flag("malware");
    let mut set = default_pack().clone();
    let before = evaluate(&signals, &ctx("a@example.com.au"), &set);
    let mut trial = policy(
        "trial-deliver",
        Scope::User("a@example.com.au".into()),
        1,
        vec![Action::Bcc("audit@example.com.au".into()), Action::Deliver],
    );
    trial.dry_run = true;
    set.policies.push(trial);
    let after = evaluate(&signals, &ctx("a@example.com.au"), &set);
    assert_eq!(before.verdict, after.verdict);
    assert_eq!(before.actions, after.actions);
    assert!(after
        .matched
        .iter()
        .any(|m| m.id == "trial-deliver" && m.dry_run));
}

#[test]
fn specificity_beats_priority_and_priority_orders_within_a_scope() {
    let set = PolicySet {
        groups: [("finance".into(), vec!["pay@example.com.au".into()])].into(),
        policies: vec![
            policy(
                "global",
                Scope::Global,
                1,
                vec![Action::Quarantine("q".into())],
            ),
            policy("tenant", Scope::Tenant, 50, vec![Action::Discard]),
            policy(
                "domain",
                Scope::Domain("example.com.au".into()),
                50,
                vec![Action::Reject { code: 550 }],
            ),
            policy(
                "domain-first",
                Scope::Domain("example.com.au".into()),
                10,
                vec![Action::Reject { code: 554 }],
            ),
            policy(
                "group",
                Scope::Group("finance".into()),
                99,
                vec![Action::Defer],
            ),
            policy(
                "user",
                Scope::User("boss@example.com.au".into()),
                99,
                vec![Action::Deliver],
            ),
        ],
    };
    let signals = Signals::default();
    let verdict = |rcpt: &str| evaluate(&signals, &ctx(rcpt), &set).verdict;
    assert_eq!(verdict("boss@example.com.au"), Verdict::Deliver);
    assert!(matches!(
        verdict("pay@example.com.au"),
        Verdict::Defer { .. }
    ));
    assert!(matches!(
        verdict("other@example.com.au"),
        Verdict::Reject { code: 554, .. }
    ));
    assert_eq!(verdict("other@elsewhere.test"), Verdict::Discard);
    let other_tenant = Context {
        tenant_id: Some("t2"),
        ..ctx("boss@example.com.au")
    };
    assert!(matches!(
        evaluate(&signals, &other_tenant, &set).verdict,
        Verdict::Quarantine { .. }
    ));
}

#[test]
fn outbound_scope_follows_the_sender() {
    let set = PolicySet {
        policies: vec![policy(
            "outbound-tls",
            Scope::Domain("example.com.au".into()),
            10,
            vec![Action::RequireTls],
        )],
        ..Default::default()
    };
    let out = Context {
        tenant_id: Some("t1"),
        direction: Direction::Outbound,
        sender: "staff@example.com.au",
        recipient: "partner@elsewhere.test",
    };
    let decision = evaluate(&Signals::default(), &out, &set);
    assert_eq!(decision.actions, vec![Action::RequireTls]);
    assert_eq!(decision.verdict, Verdict::Deliver);
}

#[test]
fn conditions_on_direction_sender_recipient_group_counts_marking_and_auth() {
    let mut p = policy("all", Scope::Global, 1, vec![Action::Discard]);
    p.conditions = vec![
        Condition::Direction(currawong_policy::Flow::Inbound),
        Condition::Sender("*@sender.test".into()),
        Condition::Recipient("pay@example.com.au".into()),
        Condition::Group("finance".into()),
        Condition::Count {
            name: "dlp.tfn".into(),
            at_least: 5,
        },
        Condition::Marking("OFFICIAL:Sensitive".into()),
        Condition::Auth {
            method: "spf".into(),
            result: "FAIL".into(),
        },
    ];
    let set = PolicySet {
        groups: [("finance".into(), vec!["PAY@example.com.au".into()])].into(),
        policies: vec![p],
    };
    let mut signals = Signals::from_report(&{
        let mut r = report();
        r.auth = Some(spoofed());
        r
    });
    signals.count("dlp.tfn", 5);
    signals.marking = Some("official:sensitive".into());
    let hit = evaluate(&signals, &ctx("pay@example.com.au"), &set);
    assert_eq!(hit.verdict, Verdict::Discard);
    signals.count("dlp.tfn", 4);
    let miss = evaluate(&signals, &ctx("pay@example.com.au"), &set);
    assert_eq!(miss.verdict, Verdict::Deliver);
}

#[test]
fn recipients_that_differ_split_the_message() {
    let set = PolicySet {
        policies: vec![policy(
            "boss-bcc",
            Scope::User("boss@example.com.au".into()),
            1,
            vec![Action::Bcc("audit@example.com.au".into())],
        )],
        ..Default::default()
    };
    let recipients = vec![
        "a@example.com.au".to_string(),
        "boss@example.com.au".to_string(),
        "b@example.com.au".to_string(),
    ];
    let msg = Message {
        tenant_id: Some("t1"),
        direction: Direction::Inbound,
        sender: "x@sender.test",
        recipients: &recipients,
    };
    let decision = evaluate_signals(&Signals::default(), &msg, &set);
    let groups: Vec<Vec<&str>> = decision
        .split()
        .iter()
        .map(|g| g.iter().map(|d| d.recipient.as_str()).collect())
        .collect();
    assert_eq!(
        groups,
        vec![
            vec!["a@example.com.au", "b@example.com.au"],
            vec!["boss@example.com.au"]
        ]
    );
}

#[test]
fn defer_signal_is_never_delivered() {
    let set = PolicySet {
        policies: vec![policy("allow", Scope::Global, 1, vec![Action::Deliver])],
        ..Default::default()
    };
    let mut signals = Signals::default();
    signals.flag("defer");
    assert!(matches!(
        evaluate(&signals, &ctx("a@example.com.au"), &set).verdict,
        Verdict::Defer { .. }
    ));
}

#[test]
fn invalid_policies_are_refused() {
    let base = || policy("p", Scope::Global, 1, vec![]);
    let mut header = base();
    header.actions.push(Action::AddHeader {
        name: "X-A".into(),
        value: "x\r\nBcc: evil@attacker.test".into(),
    });
    let mut tenant = base();
    tenant.tenant_id = Some("t1".into());
    let mut auth = base();
    auth.conditions.push(Condition::Auth {
        method: "dkmi".into(),
        result: "pass".into(),
    });
    let mut redirect = base();
    redirect
        .actions
        .push(Action::Redirect("not an address".into()));
    for bad in [header, tenant, auth, redirect] {
        assert!(bad.validate().is_err(), "{bad:?}");
    }
    let dup = PolicySet {
        policies: vec![base(), base()],
        ..Default::default()
    };
    assert!(dup.validate().is_err());
    assert!(PolicySet::from_toml("[[policy]]\nid = \"x\"\nscope = \"galaxy\"\n").is_err());
}

#[test]
fn pack_round_trips_through_toml_and_the_store() {
    let mut pack = default_pack().clone();
    pack.groups
        .insert("finance".into(), vec!["pay@example.com.au".into()]);
    pack.policies.push(Policy {
        dry_run: true,
        ..policy(
            "finance-banner",
            Scope::Group("finance".into()),
            5,
            vec![Action::Banner("External sender".into()), Action::Encrypt],
        )
    });
    let text = pack.to_toml().unwrap();
    assert_eq!(PolicySet::from_toml(&text).unwrap(), pack);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.db");
    let mut store = PolicyStore::open(&path).unwrap();
    assert!(store.is_empty().unwrap());
    store.import_toml(&text).unwrap();
    let mut loaded = store.load().unwrap();
    loaded.policies.sort_by(|a, b| a.id.cmp(&b.id));
    let mut expected = pack.clone();
    expected.policies.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(loaded, expected);
    assert_eq!(
        PolicySet::from_toml(&store.export_toml().unwrap()).unwrap(),
        loaded
    );

    let mut edited = store.get("spam-tag").unwrap().unwrap();
    edited.enabled = false;
    store.upsert(&edited).unwrap();
    assert!(store.delete("malware").unwrap());
    assert!(!store.delete("malware").unwrap());
    store.set_group("finance", &[]).unwrap();
    drop(store);

    // Reopening runs no migration twice and keeps the edits.
    let store = PolicyStore::open(&path).unwrap();
    let set = store.load().unwrap();
    assert!(set.policies.iter().all(|p| p.id != "malware"));
    assert!(
        !set.policies
            .iter()
            .find(|p| p.id == "spam-tag")
            .unwrap()
            .enabled
    );
    assert!(set.groups.is_empty());
    let mut bad = edited;
    bad.actions = vec![Action::Reject { code: 250 }];
    assert!(store.upsert(&bad).is_err());
}

#[test]
fn load_seeds_an_empty_database_from_the_pack() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = currawong_core::config::PolicyConfig {
        pack: None,
        database: Some(dir.path().join("policy.db")),
    };
    let set = currawong_policy::load(&cfg).unwrap();
    assert_eq!(set.policies.len(), default_pack().policies.len());
    let pack_path = dir.path().join("pack.toml");
    std::fs::write(
        &pack_path,
        "[[policy]]\nid = \"only\"\nactions = [\"deliver\"]\n",
    )
    .unwrap();
    let file_only = currawong_core::config::PolicyConfig {
        pack: Some(pack_path),
        database: None,
    };
    assert_eq!(
        currawong_policy::load(&file_only).unwrap().policies.len(),
        1
    );
}
