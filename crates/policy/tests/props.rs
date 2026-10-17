use currawong_core::{Direction, Verdict};
use currawong_policy::{
    evaluate, evaluate_signals, Action, Condition, Context, Policy, PolicySet, Scope, Signals,
};
use proptest::prelude::*;

const ADDRESSES: [&str; 4] = [
    "a@example.com.au",
    "b@example.com.au",
    "c@other.test",
    "ceo@example.com.au",
];
const TENANTS: [&str; 2] = ["t1", "t2"];
const FLAGS: [&str; 4] = ["malware", "defer", "active_content", "fail_closed"];

fn scope() -> impl Strategy<Value = Scope> {
    prop_oneof![
        Just(Scope::Global),
        Just(Scope::Tenant),
        Just(Scope::Domain("example.com.au".into())),
        Just(Scope::Group("finance".into())),
        (0..ADDRESSES.len()).prop_map(|i| Scope::User(ADDRESSES[i].into())),
    ]
}

fn condition() -> impl Strategy<Value = Condition> {
    prop_oneof![
        (0..FLAGS.len()).prop_map(|i| Condition::Flag(FLAGS[i].into())),
        (0.0..12.0f64).prop_map(|min| Condition::Score {
            name: "spam".into(),
            at_least: Some(min),
            below: None,
        }),
        (0..ADDRESSES.len()).prop_map(|i| Condition::Recipient(ADDRESSES[i].into())),
        Just(Condition::Group("finance".into())),
    ]
}

fn action() -> impl Strategy<Value = Action> {
    prop_oneof![
        Just(Action::Deliver),
        Just(Action::Quarantine("q".into())),
        Just(Action::Reject { code: 550 }),
        Just(Action::Discard),
        Just(Action::Defer),
        Just(Action::AddHeader {
            name: "X-Test".into(),
            value: "1".into()
        }),
        Just(Action::Bcc("audit@example.com.au".into())),
    ]
}

/// Tenant-authored and platform policies, never a floor override.
fn policies() -> impl Strategy<Value = Vec<Policy>> {
    prop::collection::vec(
        (
            scope(),
            0..TENANTS.len(),
            -5i64..5,
            any::<(bool, bool, bool)>(),
            prop::collection::vec(condition(), 0..3),
            prop::collection::vec(action(), 0..3),
        ),
        0..8,
    )
    .prop_map(|items| {
        items
            .into_iter()
            .enumerate()
            .map(
                |(
                    i,
                    (scope, tenant, priority, (enabled, dry_run, mandatory), conditions, actions),
                )| {
                    Policy {
                        id: format!("p{i}"),
                        tenant_id: (scope != Scope::Global).then(|| TENANTS[tenant].to_string()),
                        scope,
                        priority,
                        enabled,
                        dry_run,
                        mandatory,
                        override_floor: Vec::new(),
                        conditions,
                        actions,
                    }
                },
            )
            .collect()
    })
}

fn signals() -> impl Strategy<Value = Signals> {
    (
        prop::collection::vec(any::<bool>(), FLAGS.len()),
        0.0..12.0f64,
    )
        .prop_map(|(set, spam)| {
            let mut signals = Signals::default();
            for (flag, on) in FLAGS.iter().zip(set) {
                if on {
                    signals.flag(flag);
                }
            }
            signals.score("spam", spam);
            signals
        })
}

/// Recipient address, tenant and direction, as the pipeline resolves them.
fn recipients() -> impl Strategy<Value = Vec<(usize, usize, bool)>> {
    prop::collection::vec((0..ADDRESSES.len(), 0..TENANTS.len(), any::<bool>()), 1..5)
}

fn contexts(rcpts: &[(usize, usize, bool)]) -> Vec<Context<'static>> {
    rcpts
        .iter()
        .map(|&(addr, tenant, outbound)| Context {
            tenant_id: Some(TENANTS[tenant]),
            direction: if outbound {
                Direction::Outbound
            } else {
                Direction::Inbound
            },
            sender: "x@sender.test",
            sender_identity: Some("ceo@example.com.au"),
            recipient: ADDRESSES[addr],
        })
        .collect()
}

fn set(policies: Vec<Policy>) -> PolicySet {
    PolicySet {
        groups: [("finance".into(), vec!["b@example.com.au".into()])].into(),
        tenant_groups: [(
            "t1".into(),
            [("finance".into(), vec!["a@example.com.au".into()])].into(),
        )]
        .into(),
        policies,
    }
}

proptest! {
    #[test]
    fn exactly_one_verdict_per_recipient(policies in policies(), signals in signals(), rcpts in recipients()) {
        let set = set(policies);
        let ctxs = contexts(&rcpts);
        let decision = evaluate_signals(&signals, &ctxs, &set);
        prop_assert_eq!(decision.decisions.len(), ctxs.len());
        // Every recipient lands in exactly one split group.
        let groups = decision.split();
        let mut seen = vec![0usize; ctxs.len()];
        for group in &groups {
            for d in group {
                let i = decision.decisions.iter().position(|x| std::ptr::eq(x, *d)).unwrap();
                seen[i] += 1;
                prop_assert_eq!(&d.verdict, &group[0].verdict);
                prop_assert_eq!(&d.actions, &group[0].actions);
            }
        }
        prop_assert!(seen.iter().all(|n| *n == 1), "{:?}", seen);
        for (d, ctx) in decision.decisions.iter().zip(&ctxs) {
            // Deciding the recipient alone gives the same answer.
            prop_assert_eq!(d, &evaluate(&signals, ctx, &set));
            prop_assert_eq!(&d.recipient, ctx.recipient);
            prop_assert!(d.actions.iter().filter(|a| a.is_terminal()).count() <= 1);
            prop_assert!(!d.explanation.is_empty());
        }
    }

    #[test]
    fn no_tenant_or_platform_pack_can_release_malware_or_failed_scans(policies in policies(), signals in signals(), rcpts in recipients()) {
        let set = set(policies);
        let decision = evaluate_signals(&signals, &contexts(&rcpts), &set);
        for d in &decision.decisions {
            let flag = |name: &str| signals.flags.contains(name);
            if flag("malware") || (flag("fail_closed") && !flag("defer")) {
                prop_assert!(matches!(d.verdict, Verdict::Quarantine { .. }), "{:?}", d);
            } else if flag("defer") {
                prop_assert!(matches!(d.verdict, Verdict::Defer { .. }), "{:?}", d);
            }
        }
    }

    #[test]
    fn dry_run_policies_never_change_verdicts(policies in policies(), extra in policies(), signals in signals(), rcpts in recipients()) {
        let base = set(policies.clone());
        let mut with = policies;
        with.extend(extra.into_iter().map(|mut p| { p.id = format!("dry-{}", p.id); p.dry_run = true; p }));
        let with = set(with);
        let ctxs = contexts(&rcpts);
        let a = evaluate_signals(&signals, &ctxs, &base);
        let b = evaluate_signals(&signals, &ctxs, &with);
        for (x, y) in a.decisions.iter().zip(&b.decisions) {
            prop_assert_eq!(&x.verdict, &y.verdict);
            prop_assert_eq!(&x.actions, &y.actions);
        }
    }

    #[test]
    fn policy_order_in_the_pack_does_not_matter(policies in policies(), signals in signals(), rcpts in recipients()) {
        let forward = set(policies.clone());
        let mut reversed = policies;
        reversed.reverse();
        let reversed = set(reversed);
        let ctxs = contexts(&rcpts);
        prop_assert_eq!(evaluate_signals(&signals, &ctxs, &forward), evaluate_signals(&signals, &ctxs, &reversed));
    }
}
