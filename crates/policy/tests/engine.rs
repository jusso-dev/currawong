use currawong_core::{AuthMethodResult, AuthResults, Direction, MessageId, ScanReport, Verdict};
use currawong_policy::{
    decide, default_pack, evaluate, evaluate_signals, Action, Condition, Context, Policy,
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
        sender_identity: None,
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
        mandatory: false,
        override_floor: Vec::new(),
        conditions: Vec::new(),
        actions,
    }
}

fn set(policies: Vec<Policy>) -> PolicySet {
    PolicySet {
        policies,
        ..Default::default()
    }
}

fn flagged(flag: &str) -> Signals {
    let mut signals = Signals::default();
    signals.flag(flag);
    signals
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
        dmarc_domain: "example.com.au".into(),
        header: String::new(),
    }
}

fn default_verdict(signals: &Signals) -> Verdict {
    evaluate(signals, &ctx("user@example.com.au"), default_pack()).verdict
}

fn quarantine(reason: &str) -> Verdict {
    Verdict::Quarantine {
        reason: reason.into(),
    }
}

#[test]
fn default_pack_and_floor_cover_each_signal() {
    for (flag, id) in [
        ("malware", "malware"),
        ("active_content", "active-content"),
        ("fail_closed", "scan-failed"),
    ] {
        assert_eq!(default_verdict(&flagged(flag)), quarantine(id), "{flag}");
    }
    assert!(matches!(
        default_verdict(&flagged("defer")),
        Verdict::Defer { .. }
    ));
    let mut spoof = report();
    spoof.auth = Some(spoofed());
    assert_eq!(
        default_verdict(&Signals::from_report(&spoof)),
        quarantine("dmarc-reject")
    );
    // DMARC fail under p=none is delivered.
    spoof.auth.as_mut().unwrap().dmarc_policy = "none".into();
    assert_eq!(
        default_verdict(&Signals::from_report(&spoof)),
        Verdict::Deliver
    );

    let mut spam = Signals::default();
    spam.score("spam", 9.5);
    assert_eq!(default_verdict(&spam), quarantine("spam-quarantine"));
    spam.score("spam", 8.0);
    assert_eq!(default_verdict(&spam), quarantine("spam-quarantine"));
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
    assert_eq!(decide(&infected), quarantine("malware"));
    let mut deferred = report();
    deferred.defer = true;
    deferred.active_content = true;
    assert!(matches!(decide(&deferred), Verdict::Defer { .. }));
    assert_eq!(decide(&report()), Verdict::Deliver);
}

#[test]
fn default_pack_holds_outbound_dlp_findings() {
    use currawong_core::{DlpKind, DlpReport};
    let outbound = Context {
        direction: Direction::Outbound,
        ..ctx("agent@external.test")
    };
    let verdict = |dlp: DlpReport, ctx: &Context| {
        let mut scanned = report();
        scanned.dlp = Some(dlp);
        evaluate(&Signals::from_report(&scanned), ctx, default_pack()).verdict
    };
    let with = |kind: DlpKind, count: u32| DlpReport {
        counts: [(kind, count)].into(),
        ..DlpReport::default()
    };
    assert_eq!(
        verdict(with(DlpKind::Tfn, 5), &outbound),
        quarantine("dlp-tfn")
    );
    assert_eq!(verdict(with(DlpKind::Tfn, 4), &outbound), Verdict::Deliver);
    assert_eq!(
        verdict(with(DlpKind::Medicare, 5), &outbound),
        quarantine("dlp-medicare")
    );
    assert_eq!(
        verdict(with(DlpKind::Card, 7), &outbound),
        quarantine("dlp-card")
    );
    assert_eq!(
        verdict(with(DlpKind::DriverLicence, 5), &outbound),
        quarantine("dlp-driver-licence")
    );
    // ABNs and ACNs are public; inbound mail is not held by the default pack.
    assert_eq!(verdict(with(DlpKind::Abn, 9), &outbound), Verdict::Deliver);
    assert_eq!(verdict(with(DlpKind::Acn, 9), &outbound), Verdict::Deliver);
    assert_eq!(
        verdict(with(DlpKind::Tfn, 5), &ctx("user@example.com.au")),
        Verdict::Deliver
    );
    let partial = DlpReport {
        incomplete: true,
        ..DlpReport::default()
    };
    assert_eq!(verdict(partial, &outbound), quarantine("dlp-incomplete"));
    let mut scanned = report();
    scanned.dlp = Some(with(DlpKind::Tfn, 5));
    assert_eq!(
        Signals::from_report(&scanned).counts.get("dlp.tfn"),
        Some(&5)
    );
}

#[test]
fn floor_cannot_be_overridden_by_tenant_policies_or_an_operator_pack() {
    let user_deliver = policy(
        "vip",
        Scope::User("ceo@example.com.au".into()),
        1,
        vec![Action::Deliver],
    );
    let tenant_deliver = policy("all", Scope::Tenant, 1, vec![Action::Deliver]);
    // An operator pack with no malware policy at all.
    let pack = set(vec![user_deliver, tenant_deliver]);
    for flag in ["malware", "fail_closed"] {
        let decision = evaluate(&flagged(flag), &ctx("ceo@example.com.au"), &pack);
        assert!(
            matches!(decision.verdict, Verdict::Quarantine { .. }),
            "{flag}: {decision:?}"
        );
        assert!(decision.matched[0].id.starts_with("floor:"));
    }
    assert!(matches!(
        evaluate(&flagged("defer"), &ctx("ceo@example.com.au"), &pack).verdict,
        Verdict::Defer { .. }
    ));
    // Active content is pack policy, so a tenant may allow it.
    assert_eq!(
        evaluate(
            &flagged("active_content"),
            &ctx("ceo@example.com.au"),
            &pack
        )
        .verdict,
        Verdict::Deliver
    );

    let mut tenant_override = policy("t-override", Scope::Tenant, 1, vec![Action::Deliver]);
    tenant_override.override_floor = vec!["malware".into()];
    tenant_override.conditions = vec![Condition::Flag("malware".into())];
    assert!(tenant_override.validate().is_err());
    let mut user_override = policy("u", Scope::User("a@x.test".into()), 1, vec![]);
    user_override.tenant_id = None;
    user_override.override_floor = vec!["malware".into()];
    user_override.conditions = vec![Condition::Flag("malware".into())];
    assert!(user_override.validate().is_err());

    let mut platform = policy("lab", Scope::Global, 1, vec![Action::Deliver]);
    platform.override_floor = vec!["malware".into()];
    platform.conditions = vec![Condition::Recipient("malware-lab@example.com.au".into())];
    let pack = set(vec![platform]);
    assert_eq!(
        evaluate(
            &flagged("malware"),
            &ctx("malware-lab@example.com.au"),
            &pack
        )
        .verdict,
        Verdict::Deliver
    );
    assert!(matches!(
        evaluate(&flagged("malware"), &ctx("someone@example.com.au"), &pack).verdict,
        Verdict::Quarantine { .. }
    ));

    // Lifting malware does not lift a failed scan on the same message.
    let mut both = flagged("malware");
    both.flag("fail_closed");
    assert_eq!(
        evaluate(&both, &ctx("malware-lab@example.com.au"), &pack).verdict,
        quarantine("scan-failed")
    );
    // A floor override must say what it matches and which rule it lifts.
    let mut blanket = policy("blanket", Scope::Global, 1, vec![Action::Deliver]);
    blanket.override_floor = vec!["malware".into()];
    assert!(blanket.validate().is_err());
    blanket.conditions = vec![Condition::Flag("malware".into())];
    assert!(blanket.validate().is_ok());
    blanket.override_floor = vec!["everything".into()];
    assert!(blanket.validate().is_err());
}

#[test]
fn enforced_marks_platform_and_mandatory_actions() {
    let header = |name: &str| Action::AddHeader {
        name: name.into(),
        value: "1".into(),
    };
    let platform = policy("platform", Scope::Global, 3, vec![header("X-Platform")]);
    let tenant = policy("tenant", Scope::Tenant, 1, vec![header("X-Tenant")]);
    let mut locked = policy("locked", Scope::Tenant, 2, vec![header("X-Locked")]);
    locked.mandatory = true;
    let decision = evaluate(
        &Signals::default(),
        &ctx("a@example.com.au"),
        &set(vec![platform, tenant, locked]),
    );
    assert_eq!(
        decision.actions,
        [header("X-Tenant"), header("X-Locked"), header("X-Platform")]
    );
    assert_eq!(decision.enforced, [false, true, true]);
}

#[test]
fn split_keeps_tenants_apart() {
    let contexts = [
        ctx("a@example.com.au"),
        Context {
            tenant_id: Some("t2"),
            ..ctx("b@other.test")
        },
    ];
    let decision = evaluate_signals(&Signals::default(), &contexts, &set(vec![]));
    assert_eq!(decision.decisions[0].verdict, decision.decisions[1].verdict);
    assert_eq!(decision.split().len(), 2);
}

#[test]
fn tagged_policy_address_is_not_widened() {
    let pack = set(vec![policy(
        "vip-tag",
        Scope::User("ceo+vip@example.com.au".into()),
        1,
        vec![Action::Discard],
    )]);
    assert_eq!(
        evaluate(&Signals::default(), &ctx("ceo@example.com.au"), &pack).verdict,
        Verdict::Deliver
    );
    let mut group = PolicySet {
        groups: [("vip".into(), vec!["ceo+vip@example.com.au".into()])].into(),
        ..Default::default()
    };
    assert!(!group.in_group(None, "vip", "ceo@example.com.au"));
    group
        .groups
        .insert("all".into(), vec!["ceo@example.com.au".into()]);
    assert!(group.in_group(None, "all", "ceo+news@example.com.au"));
}

#[test]
fn ids_queues_and_tenants_are_restricted() {
    let mut p = policy("ok.id_1-x", Scope::Global, 1, vec![]);
    assert!(p.validate().is_ok());
    for id in [
        "",
        "has space",
        "line\r\nbreak",
        "ünïcode",
        "a".repeat(65).as_str(),
    ] {
        p.id = id.to_string();
        assert!(p.validate().is_err(), "{id:?}");
    }
    let queue = policy(
        "q",
        Scope::Global,
        1,
        vec![Action::Quarantine("bad queue".into())],
    );
    assert!(queue.validate().is_err());
    for tenant in ["", " ", "t1 "] {
        let mut p = policy("t", Scope::Tenant, 1, vec![]);
        p.tenant_id = Some(tenant.into());
        assert!(p.validate().is_err(), "{tenant:?}");
        let mut store = PolicyStore::open_in_memory().unwrap();
        p.tenant_id = None;
        assert!(store.upsert(Some(tenant), &p).is_err(), "{tenant:?}");
        assert!(store.set_group(Some(tenant), "g", &[]).is_err());
        let groups = PolicySet {
            tenant_groups: [(tenant.to_string(), Default::default())].into(),
            ..Default::default()
        };
        assert!(groups.validate().is_err());
    }
}

#[test]
fn old_layout_database_is_refused() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("old.db");
    let conn = rusqlite::Connection::open(&path).unwrap();
    conn.execute_batch(
        "CREATE TABLE policies (id TEXT PRIMARY KEY, tenant_id TEXT, scope_kind TEXT NOT NULL, \
         scope_value TEXT, priority INTEGER NOT NULL, enabled INTEGER NOT NULL DEFAULT 1, \
         dry_run INTEGER NOT NULL DEFAULT 0, conditions TEXT NOT NULL, actions TEXT NOT NULL); \
         PRAGMA user_version = 1;",
    )
    .unwrap();
    drop(conn);
    let err = PolicyStore::open(&path).err().expect("old layout refused");
    assert!(err.to_string().contains("old layout"), "{err}");
}

#[test]
fn stamp_follows_store_writes_and_a_seeded_database_ignores_the_pack() {
    let dir = tempfile::tempdir().unwrap();
    let pack = dir.path().join("pack.toml");
    std::fs::write(&pack, "[[policy]]\nid = \"one\"\nactions = [\"deliver\"]\n").unwrap();
    let cfg = currawong_core::config::PolicyConfig {
        pack: Some(pack.clone()),
        database: Some(dir.path().join("policy.db")),
        forward_domains: Vec::new(),
    };
    assert_eq!(currawong_policy::load(&cfg).unwrap().policies.len(), 1);
    let before = currawong_policy::stamp(&cfg).unwrap();
    assert_eq!(currawong_policy::stamp(&cfg).unwrap(), before);
    // A broken pack no longer matters once the database is seeded.
    std::fs::write(&pack, "not toml [").unwrap();
    let mut store = PolicyStore::open(cfg.database.as_ref().unwrap()).unwrap();
    store
        .upsert(
            None,
            &policy("two", Scope::Global, 1, vec![Action::Discard]),
        )
        .unwrap();
    assert_ne!(currawong_policy::stamp(&cfg).unwrap(), before);
    assert_eq!(currawong_policy::load(&cfg).unwrap().policies.len(), 2);
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
    header
        .conditions
        .push(Condition::Flag("active_content".into()));
    let hold = policy(
        "active",
        Scope::Global,
        10,
        vec![Action::Quarantine("active".into())],
    );
    let mut trial = policy("trial-reject", Scope::Global, 5, vec![Action::Discard]);
    trial.dry_run = true;
    let pack = set(vec![hold, trial, header]);
    let decision = evaluate(
        &flagged("active_content"),
        &ctx("ceo@example.com.au"),
        &pack,
    );
    let ids: Vec<&str> = decision.matched.iter().map(|m| m.id.as_str()).collect();
    assert_eq!(ids, ["vip-header", "trial-reject", "active"]);
    for id in ids {
        assert!(
            decision.explanation.iter().any(|line| line.starts_with(id)),
            "{id} missing from {:?}",
            decision.explanation
        );
    }
    assert!(decision.explanation[1].contains("dry run"));
    assert_eq!(decision.verdict, quarantine("active"));
    assert_eq!(decision.queue(), Some("active"));
}

#[test]
fn dry_run_policy_does_not_change_the_verdict() {
    let signals = flagged("active_content");
    let mut pack = default_pack().clone();
    let before = evaluate(&signals, &ctx("a@example.com.au"), &pack);
    let mut trial = policy(
        "trial-deliver",
        Scope::User("a@example.com.au".into()),
        1,
        vec![Action::Bcc("audit@example.com.au".into()), Action::Deliver],
    );
    trial.dry_run = true;
    pack.policies.push(trial);
    let after = evaluate(&signals, &ctx("a@example.com.au"), &pack);
    assert_eq!(before.verdict, after.verdict);
    assert_eq!(before.actions, after.actions);
    assert!(after
        .matched
        .iter()
        .any(|m| m.id == "trial-deliver" && m.dry_run));
}

#[test]
fn mandatory_policies_add_actions_after_a_more_specific_verdict() {
    let deliver = policy(
        "vip",
        Scope::User("ceo@example.com.au".into()),
        1,
        vec![Action::Deliver],
    );
    let journal = Action::AddHeader {
        name: "X-Journal".into(),
        value: "yes".into(),
    };
    let mut compliance = policy("compliance", Scope::Global, 1, vec![journal.clone()]);
    let optional = evaluate(
        &Signals::default(),
        &ctx("ceo@example.com.au"),
        &set(vec![deliver.clone(), compliance.clone()]),
    );
    assert!(!optional.actions.contains(&journal));
    compliance.mandatory = true;
    let decision = evaluate(
        &Signals::default(),
        &ctx("ceo@example.com.au"),
        &set(vec![deliver, compliance]),
    );
    assert_eq!(decision.verdict, Verdict::Deliver);
    assert!(decision.actions.contains(&journal), "{decision:?}");
}

#[test]
fn specificity_beats_priority_and_priority_orders_within_a_scope() {
    let pack = PolicySet {
        tenant_groups: [(
            "t1".into(),
            [("finance".into(), vec!["pay@example.com.au".into()])].into(),
        )]
        .into(),
        ..set(vec![
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
        ])
    };
    let signals = Signals::default();
    let verdict = |rcpt: &str| evaluate(&signals, &ctx(rcpt), &pack).verdict;
    assert_eq!(verdict("boss@example.com.au"), Verdict::Deliver);
    // Sub-addressing and a trailing dot do not dodge user and domain scope.
    assert_eq!(verdict("Boss+news@Example.com.au."), Verdict::Deliver);
    assert!(matches!(
        verdict("pay@example.com.au"),
        Verdict::Defer { .. }
    ));
    assert!(matches!(
        verdict("other@example.com.au."),
        Verdict::Reject { code: 554, .. }
    ));
    assert_eq!(verdict("other@elsewhere.test"), Verdict::Discard);
    let other_tenant = Context {
        tenant_id: Some("t2"),
        ..ctx("boss@example.com.au")
    };
    assert!(matches!(
        evaluate(&signals, &other_tenant, &pack).verdict,
        Verdict::Quarantine { .. }
    ));
}

#[test]
fn groups_belong_to_their_tenant() {
    let mut finance = policy(
        "finance",
        Scope::Group("finance".into()),
        1,
        vec![Action::Discard],
    );
    finance.tenant_id = Some("t2".into());
    let pack = PolicySet {
        groups: [("finance".into(), vec!["pay@example.com.au".into()])].into(),
        tenant_groups: [(
            "t1".into(),
            [("finance".into(), vec!["pay@example.com.au".into()])].into(),
        )]
        .into(),
        ..set(vec![finance])
    };
    // pay@ is in t1's and the platform's "finance", not t2's.
    let t2 = Context {
        tenant_id: Some("t2"),
        ..ctx("pay@example.com.au")
    };
    assert_eq!(
        evaluate(&Signals::default(), &t2, &pack).verdict,
        Verdict::Deliver
    );
}

#[test]
fn outbound_user_scope_needs_the_authenticated_identity() {
    let mut exempt = policy(
        "ceo-exempt",
        Scope::User("ceo@example.com.au".into()),
        1,
        vec![Action::Discard],
    );
    exempt
        .conditions
        .push(Condition::Direction(currawong_policy::Flow::Outbound));
    let domain = policy(
        "domain-header",
        Scope::Domain("example.com.au".into()),
        1,
        vec![Action::AddHeader {
            name: "X-Out".into(),
            value: "1".into(),
        }],
    );
    let pack = set(vec![exempt, domain]);
    let forged = Context {
        tenant_id: Some("t1"),
        direction: Direction::Outbound,
        sender: "ceo@example.com.au",
        sender_identity: None,
        recipient: "partner@elsewhere.test",
    };
    let decision = evaluate(&Signals::default(), &forged, &pack);
    assert_eq!(decision.verdict, Verdict::Deliver);
    assert_eq!(decision.matched.len(), 1, "{decision:?}");
    let logged_in = Context {
        sender_identity: Some("ceo@example.com.au"),
        ..forged
    };
    assert_eq!(
        evaluate(&Signals::default(), &logged_in, &pack).verdict,
        Verdict::Discard
    );
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
    let pack = PolicySet {
        groups: [("finance".into(), vec!["PAY@example.com.au".into()])].into(),
        ..set(vec![p])
    };
    let mut signals = Signals::from_report(&{
        let mut r = report();
        r.auth = Some(spoofed());
        r
    });
    signals.count("dlp.tfn", 5);
    signals.marking = Some("official:sensitive".into());
    let hit = evaluate(&signals, &ctx("pay+x@example.com.au"), &pack);
    assert_eq!(hit.verdict, Verdict::Discard);
    signals.count("dlp.tfn", 4);
    let miss = evaluate(&signals, &ctx("pay@example.com.au"), &pack);
    assert_eq!(miss.verdict, Verdict::Deliver);
}

#[test]
fn recipients_that_differ_split_and_the_combined_verdict_never_discards_everyone() {
    let pack = set(vec![policy(
        "boss-drop",
        Scope::User("boss@example.com.au".into()),
        1,
        vec![Action::Discard],
    )]);
    let contexts = [
        ctx("a@example.com.au"),
        ctx("boss@example.com.au"),
        ctx("b@example.com.au"),
    ];
    let decision = evaluate_signals(&Signals::default(), &contexts, &pack);
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
    assert_eq!(decision.verdict(), Verdict::Deliver);
}

#[test]
fn invalid_policies_are_refused() {
    let base = || policy("p", Scope::Global, 1, vec![]);
    let with = |action: Action| {
        let mut p = base();
        p.actions.push(action);
        p
    };
    let header = |name: &str, value: &str| {
        with(Action::AddHeader {
            name: name.into(),
            value: value.into(),
        })
    };
    let score = |at_least: Option<f64>, below: Option<f64>| {
        let mut p = base();
        p.conditions.push(Condition::Score {
            name: "spam".into(),
            at_least,
            below,
        });
        p
    };
    let mut tenant = base();
    tenant.tenant_id = Some("t1".into());
    let mut auth = base();
    auth.conditions.push(Condition::Auth {
        method: "dkmi".into(),
        result: "pass".into(),
    });
    let bad = [
        header("X-A", "x\r\nBcc: evil@attacker.test"),
        header("X-A", "nul\0byte"),
        header("Authentication-Results", "forged; dmarc=pass"),
        header("arc-seal", "i=1"),
        header("Received", "from nowhere"),
        header("X-Long", &"a".repeat(1000)),
        tenant,
        auth,
        with(Action::Redirect("not an address".into())),
        with(Action::Banner("External sender".into())),
        score(Some(f64::NAN), None),
        score(None, Some(f64::INFINITY)),
        score(Some(8.0), Some(5.0)),
        score(Some(5.0), Some(5.0)),
    ];
    for policy in bad {
        assert!(policy.validate().is_err(), "{policy:?}");
    }
    assert!(header("X-Fine", "ok\tvalue").validate().is_ok());
    assert!(set(vec![base(), base()]).validate().is_err());
    assert!(PolicySet::from_toml("[[policy]]\nid = \"x\"\nscope = \"galaxy\"\n").is_err());
}

#[test]
fn pack_round_trips_through_toml_and_the_store() {
    let mut pack = default_pack().clone();
    pack.groups
        .insert("finance".into(), vec!["pay@example.com.au".into()]);
    pack.policies.push(Policy {
        dry_run: true,
        mandatory: true,
        tenant_id: None,
        ..policy(
            "finance-bcc",
            Scope::Group("finance".into()),
            5,
            vec![Action::Bcc("audit@example.com.au".into())],
        )
    });
    let text = pack.to_toml().unwrap();
    assert_eq!(PolicySet::from_toml(&text).unwrap(), pack);

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("policy.db");
    let mut store = PolicyStore::open(&path).unwrap();
    store.import_toml(None, &text).unwrap();
    let mut loaded = store.load().unwrap();
    loaded.policies.sort_by(|a, b| a.id.cmp(&b.id));
    let mut expected = pack.clone();
    expected.policies.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(loaded, expected);
    assert_eq!(
        PolicySet::from_toml(&store.export_toml(None).unwrap()).unwrap(),
        loaded
    );

    let mut edited = store.get(None, "spam-tag").unwrap().unwrap();
    edited.enabled = false;
    store.upsert(None, &edited).unwrap();
    assert!(store.delete(None, "active-content").unwrap());
    assert!(!store.delete(None, "active-content").unwrap());
    // Importing a pack without groups keeps the groups set through the API.
    store
        .set_group(None, "board", &["chair@example.com.au".into()])
        .unwrap();
    store.import(None, &store.load().unwrap()).unwrap();
    drop(store);

    // Reopening runs no migration twice and keeps the edits.
    let mut store = PolicyStore::open(&path).unwrap();
    let set = store.load().unwrap();
    assert!(set.policies.iter().all(|p| p.id != "active-content"));
    assert!(
        !set.policies
            .iter()
            .find(|p| p.id == "spam-tag")
            .unwrap()
            .enabled
    );
    assert!(set.groups.contains_key("board"));
    let mut bad = edited;
    bad.actions = vec![Action::Reject { code: 250 }];
    assert!(store.upsert(None, &bad).is_err());
}

#[test]
fn store_namespaces_keep_tenants_apart() {
    let mut store = PolicyStore::open_in_memory().unwrap();
    let platform = policy(
        "malware-extra",
        Scope::Global,
        1,
        vec![Action::Quarantine("q".into())],
    );
    store.upsert(None, &platform).unwrap();
    // Tenant B reuses the id: it gets its own row, the platform's is untouched.
    let mut mine = policy("malware-extra", Scope::Tenant, 1, vec![Action::Deliver]);
    mine.tenant_id = None;
    store.upsert(Some("b"), &mine).unwrap();
    assert_eq!(store.get(None, "malware-extra").unwrap().unwrap(), platform);
    assert_eq!(
        store
            .get(Some("b"), "malware-extra")
            .unwrap()
            .unwrap()
            .tenant_id
            .as_deref(),
        Some("b")
    );
    assert!(!store.delete(Some("a"), "malware-extra").unwrap());
    // A tenant cannot write global scope, another tenant's policy or a floor override.
    let global = policy("g", Scope::Global, 1, vec![]);
    assert!(store.upsert(Some("b"), &global).is_err());
    let mut foreign = policy("f", Scope::Tenant, 1, vec![]);
    foreign.tenant_id = Some("a".into());
    assert!(store.upsert(Some("b"), &foreign).is_err());
    let mut lift = policy("l", Scope::Tenant, 1, vec![]);
    lift.tenant_id = None;
    lift.override_floor = vec!["malware".into()];
    lift.conditions = vec![Condition::Flag("malware".into())];
    assert!(store.upsert(Some("b"), &lift).is_err());
    // Groups are per namespace.
    store
        .set_group(Some("a"), "finance", &["x@a.test".into()])
        .unwrap();
    store
        .set_group(Some("b"), "finance", &["y@b.test".into()])
        .unwrap();
    let set = store.load().unwrap();
    assert!(set.in_group(Some("a"), "finance", "x@a.test"));
    assert!(!set.in_group(Some("b"), "finance", "x@a.test"));
    assert!(!set.in_group(None, "finance", "x@a.test"));
    assert!(store.export_toml(Some("b")).unwrap().contains("y@b.test"));
    assert!(!store.export_toml(Some("b")).unwrap().contains("x@a.test"));
}

#[test]
fn load_seeds_the_database_once() {
    let dir = tempfile::tempdir().unwrap();
    let cfg = currawong_core::config::PolicyConfig {
        pack: None,
        database: Some(dir.path().join("policy.db")),
        forward_domains: Vec::new(),
    };
    let set = currawong_policy::load(&cfg).unwrap();
    assert_eq!(set.policies.len(), default_pack().policies.len());
    let mut store = PolicyStore::open(cfg.database.as_ref().unwrap()).unwrap();
    for policy in store.list(None).unwrap() {
        store.delete(None, &policy.id).unwrap();
    }
    drop(store);
    // An admin who removed every policy keeps an empty set.
    assert!(currawong_policy::load(&cfg).unwrap().policies.is_empty());

    let pack_path = dir.path().join("pack.toml");
    std::fs::write(
        &pack_path,
        "[[policy]]\nid = \"only\"\nactions = [\"deliver\"]\n",
    )
    .unwrap();
    let file_only = currawong_core::config::PolicyConfig {
        pack: Some(pack_path),
        ..Default::default()
    };
    assert_eq!(
        currawong_policy::load(&file_only).unwrap().policies.len(),
        1
    );
}

#[test]
fn yara_matches_are_signals_policies_can_act_on() {
    let mut r = report();
    r.yara.push(currawong_core::YaraMatch {
        rule: "Currawong_Bank_Detail_Change".into(),
        namespace: "bec".into(),
        tags: vec!["bec".into(), "finance".into()],
        part: "body".into(),
    });
    let signals = Signals::from_report(&r);
    assert!(signals.flags.contains("yara"));
    assert!(signals.flags.contains("yara.bec"));
    assert!(signals.flags.contains("yara.finance"));
    assert_eq!(signals.counts.get("yara"), Some(&1));
    assert!(!Signals::from_report(&report()).flags.contains("yara"));

    let mut p = policy(
        "hold-bec",
        Scope::Global,
        1,
        vec![Action::Quarantine("bec".into())],
    );
    p.conditions = vec![Condition::Flag("yara.bec".into())];
    let pack = set(vec![p]);
    let hit = evaluate(&signals, &ctx("pay@example.com.au"), &pack);
    assert!(
        matches!(hit.verdict, Verdict::Quarantine { .. }),
        "{:?}",
        hit.verdict
    );
    let clean = evaluate(
        &Signals::from_report(&report()),
        &ctx("pay@example.com.au"),
        &pack,
    );
    assert_eq!(clean.verdict, Verdict::Deliver);
}

#[test]
fn require_tls_and_encrypt_actions_load_and_apply() {
    let pack = PolicySet::from_toml(
        r#"
[[policy]]
id = "partner-tls"
conditions = [{ direction = "outbound" }, { recipient = "*@partner.example.com.au" }]
actions = ["require_tls", "encrypt"]

[[policy]]
id = "sensitive"
priority = 50
conditions = [{ direction = "outbound" }, { marking = "OFFICIAL:Sensitive" }]
actions = ["require_dane", "encrypt_smime", "encrypt_portal"]
"#,
    )
    .expect("require_tls and encrypt are accepted at load");
    let outbound = Context {
        direction: Direction::Outbound,
        ..ctx("ops@partner.example.com.au")
    };
    let decision = evaluate(&Signals::default(), &outbound, &pack);
    assert_eq!(decision.verdict, Verdict::Deliver);
    assert_eq!(decision.actions, vec![Action::RequireTls, Action::Encrypt]);
    assert!(decision.explanation[0].contains("require TLS, encrypt"));

    let marked = Signals {
        marking: Some("OFFICIAL:Sensitive".into()),
        ..Default::default()
    };
    let decision = evaluate(&marked, &outbound, &pack);
    assert_eq!(
        decision.actions,
        vec![
            Action::RequireDane,
            Action::EncryptSmime,
            Action::EncryptPortal,
            Action::RequireTls,
            Action::Encrypt
        ]
    );
    let text = pack.to_toml().unwrap();
    assert_eq!(PolicySet::from_toml(&text).unwrap(), pack);
    let mut store = PolicyStore::open_in_memory().unwrap();
    store.import(None, &pack).unwrap();
    let mut loaded = store.load().unwrap();
    loaded.policies.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(loaded.policies, pack.policies);
}

fn government_pack() -> PolicySet {
    let text = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../config/policies/government.toml"
    ))
    .unwrap();
    PolicySet::from_toml(&text).unwrap()
}

fn marked(classification: currawong_core::Classification) -> ScanReport {
    let mut scanned = report();
    scanned.marking = Some(currawong_core::MarkingReport {
        classification: Some(classification),
        header: Some(classification),
        ..Default::default()
    });
    scanned
}

#[test]
fn pspf_government_pack_contains_the_default_pack_unchanged() {
    let government = government_pack();
    for policy in &default_pack().policies {
        let found = government.policies.iter().find(|p| p.id == policy.id);
        assert_eq!(
            found,
            Some(policy),
            "{} differs from the default pack",
            policy.id
        );
    }
}

#[test]
fn pspf_government_pack_blocks_protected_outside_government() {
    use currawong_core::Classification::*;
    let pack = government_pack();
    let verdict = |scanned: &ScanReport, rcpt: &str| {
        let outbound = Context {
            direction: Direction::Outbound,
            ..ctx(rcpt)
        };
        evaluate(&Signals::from_report(scanned), &outbound, &pack).verdict
    };
    let blocked = |id: &str| Verdict::Reject {
        code: 550,
        reason: id.into(),
    };
    assert_eq!(
        verdict(&marked(Protected), "someone@gmail.com"),
        blocked("pspf-protected-external")
    );
    assert_eq!(
        verdict(&marked(Protected), "officer@finance.gov.au"),
        Verdict::Deliver
    );
    assert_eq!(
        verdict(&marked(Protected), "officer@gov.au"),
        Verdict::Deliver
    );
    assert_eq!(
        verdict(&marked(Protected), "Officer@Finance.GOV.AU."),
        Verdict::Deliver
    );
    assert_eq!(
        verdict(&marked(Protected), "x@gov.au.evil.test"),
        blocked("pspf-protected-external")
    );
    // A lookalike suffix is not a subdomain of gov.au.
    assert_eq!(
        verdict(&marked(Protected), "x@notgov.au"),
        blocked("pspf-protected-external")
    );
    assert_eq!(
        verdict(&marked(Secret), "officer@finance.gov.au"),
        blocked("pspf-secret")
    );
    assert_eq!(
        verdict(&marked(TopSecret), "someone@gmail.com"),
        blocked("pspf-secret")
    );
    assert_eq!(
        verdict(&marked(OfficialSensitive), "someone@gmail.com"),
        Verdict::Deliver
    );
    // Unmarked outbound mail from a government tenant is held.
    let mut unmarked = report();
    unmarked.marking = Some(currawong_core::MarkingReport::default());
    assert_eq!(
        verdict(&unmarked, "someone@gmail.com"),
        quarantine("pspf-required")
    );
    // No marking inspection at all (report.marking None) is left to other policies.
    assert_eq!(verdict(&report(), "someone@gmail.com"), Verdict::Deliver);
    // Inbound PROTECTED mail is not blocked by the outbound rules.
    let inbound = evaluate(
        &Signals::from_report(&marked(Protected)),
        &ctx("a@gmail.com"),
        &pack,
    );
    assert_eq!(inbound.verdict, Verdict::Deliver);

    let mut mismatch = marked(Protected);
    mismatch.marking.as_mut().unwrap().mismatch = true;
    assert_eq!(
        verdict(&mismatch, "officer@finance.gov.au"),
        quarantine("pspf-mismatch")
    );
    let mut invalid = report();
    invalid.marking = Some(currawong_core::MarkingReport {
        invalid: true,
        ..Default::default()
    });
    assert_eq!(
        verdict(&invalid, "officer@finance.gov.au"),
        quarantine("pspf-invalid")
    );
}

#[test]
fn pspf_marking_conditions_and_not_are_validated() {
    let toml = |cond: &str| {
        PolicySet::from_toml(&format!(
            "[[policy]]\nid = \"p\"\nconditions = [{cond}]\nactions = [\"deliver\"]\n"
        ))
    };
    assert!(toml(r#"{ marking_at_least = "PROTECTED" }"#).is_ok());
    assert!(toml(r#"{ marking_at_least = "CONFIDENTIAL" }"#).is_err());
    assert!(toml(r#"{ not = { recipient = "*@*.gov.au" } }"#).is_ok());
    assert!(toml(r#"{ not = { marking_at_least = "BOGUS" } }"#).is_err());
    assert!(toml(r#"{ not = { not = { flag = "x" } } }"#).is_err());
    let signals = Signals::from_report(&marked(currawong_core::Classification::Official));
    assert_eq!(signals.marking.as_deref(), Some("OFFICIAL"));
    assert!(!signals.flags.contains("pspf.missing"));
    let mut unmarked = report();
    unmarked.marking = Some(currawong_core::MarkingReport::default());
    assert!(Signals::from_report(&unmarked)
        .flags
        .contains("pspf.missing"));
}

#[test]
fn pspf_default_marking_policy_marks_unmarked_outbound_mail_when_enabled() {
    let mut pack = government_pack();
    for policy in pack.policies.iter_mut() {
        match policy.id.as_str() {
            "pspf-default-marking" => policy.enabled = true,
            "pspf-required" => policy.enabled = false,
            _ => {}
        }
    }
    let mut unmarked = report();
    unmarked.marking = Some(currawong_core::MarkingReport::default());
    let outbound = Context {
        direction: Direction::Outbound,
        ..ctx("x@gmail.com")
    };
    let decision = evaluate(&Signals::from_report(&unmarked), &outbound, &pack);
    assert_eq!(decision.verdict, Verdict::Deliver);
    assert!(decision.actions.contains(&Action::AddHeader {
        name: "X-Protective-Marking".into(),
        value: "VER=2018.6, NS=gov.au, SEC=OFFICIAL".into(),
    }));
}
