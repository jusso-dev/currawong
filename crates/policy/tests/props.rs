use currawong_core::Direction;
use currawong_policy::{
    evaluate_signals, Action, Condition, Message, Policy, PolicySet, Scope, Signals,
};
use proptest::prelude::*;

const ADDRESSES: [&str; 4] = [
    "a@example.com.au",
    "b@example.com.au",
    "c@other.test",
    "ceo@example.com.au",
];
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
        Just(Action::RequireTls),
    ]
}

fn policies() -> impl Strategy<Value = Vec<Policy>> {
    prop::collection::vec(
        (
            scope(),
            -5i64..5,
            any::<bool>(),
            any::<bool>(),
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
                |(i, (scope, priority, enabled, dry_run, conditions, actions))| Policy {
                    id: format!("p{i}"),
                    tenant_id: (scope != Scope::Global).then(|| "t1".to_string()),
                    scope,
                    priority,
                    enabled,
                    dry_run,
                    conditions,
                    actions,
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

fn recipients() -> impl Strategy<Value = Vec<String>> {
    prop::collection::vec(
        (0..ADDRESSES.len()).prop_map(|i| ADDRESSES[i].to_string()),
        1..5,
    )
}

fn set(policies: Vec<Policy>) -> PolicySet {
    PolicySet {
        groups: [("finance".into(), vec!["b@example.com.au".into()])].into(),
        policies,
    }
}

proptest! {
    #[test]
    fn exactly_one_verdict_per_recipient(policies in policies(), signals in signals(), rcpts in recipients()) {
        let set = set(policies);
        let msg = Message { tenant_id: Some("t1"), direction: Direction::Inbound, sender: "x@sender.test", recipients: &rcpts };
        let decision = evaluate_signals(&signals, &msg, &set);
        prop_assert_eq!(decision.decisions.len(), rcpts.len());
        for (d, r) in decision.decisions.iter().zip(&rcpts) {
            prop_assert_eq!(&d.recipient, r);
            // At most one terminal action took effect.
            prop_assert!(d.actions.iter().filter(|a| a.is_terminal()).count() <= 1);
            prop_assert!(!d.explanation.is_empty());
        }
        let grouped: usize = decision.split().iter().map(Vec::len).sum();
        prop_assert_eq!(grouped, rcpts.len());
    }

    #[test]
    fn dry_run_policies_never_change_verdicts(policies in policies(), extra in policies(), signals in signals(), rcpts in recipients()) {
        let base = set(policies.clone());
        let mut with = policies;
        with.extend(extra.into_iter().map(|mut p| { p.id = format!("dry-{}", p.id); p.dry_run = true; p }));
        let with = set(with);
        let msg = Message { tenant_id: Some("t1"), direction: Direction::Inbound, sender: "x@sender.test", recipients: &rcpts };
        let a = evaluate_signals(&signals, &msg, &base);
        let b = evaluate_signals(&signals, &msg, &with);
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
        let msg = Message { tenant_id: Some("t1"), direction: Direction::Inbound, sender: "x@sender.test", recipients: &rcpts };
        prop_assert_eq!(evaluate_signals(&signals, &msg, &forward), evaluate_signals(&signals, &msg, &reversed));
    }
}
