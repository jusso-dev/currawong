//! Deterministic evaluation. Policies run most specific scope first, then by
//! priority (lower first), then by id. The first matching policy with a
//! terminal action sets the verdict; non-terminal actions from every matching
//! policy up to that point are kept. Dry-run policies are explained only.
use crate::model::{Action, Condition, Flow, Policy, PolicySet, Scope};
use crate::signals::Signals;
use currawong_core::{Direction, ScanReport, Verdict};

/// The recipient being decided, and the message facts scopes need.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    pub tenant_id: Option<&'a str>,
    pub direction: Direction,
    pub sender: &'a str,
    pub recipient: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Matched {
    pub id: String,
    pub dry_run: bool,
}

/// The outcome for one recipient.
#[derive(Debug, Clone, PartialEq)]
pub struct Decision {
    pub recipient: String,
    pub verdict: Verdict,
    /// Every action that took effect, terminal one included, in order.
    pub actions: Vec<Action>,
    pub matched: Vec<Matched>,
    pub explanation: Vec<String>,
}

pub fn evaluate(signals: &Signals, ctx: &Context, set: &PolicySet) -> Decision {
    let mut order: Vec<&Policy> = set.policies.iter().filter(|p| p.enabled).collect();
    order.sort_by(|a, b| {
        b.scope
            .specificity()
            .cmp(&a.scope.specificity())
            .then(a.priority.cmp(&b.priority))
            .then(a.id.cmp(&b.id))
    });
    let mut verdict = None;
    let mut actions = Vec::new();
    let mut matched = Vec::new();
    let mut explanation = Vec::new();
    for policy in order {
        // Once decided, keep looking only so dry-run matches are still reported.
        if verdict.is_some() && !policy.dry_run {
            continue;
        }
        if !applies(policy, ctx, set)
            || !policy
                .conditions
                .iter()
                .all(|c| holds(c, signals, ctx, set))
        {
            continue;
        }
        matched.push(Matched {
            id: policy.id.clone(),
            dry_run: policy.dry_run,
        });
        let summary: Vec<String> = policy.actions.iter().map(describe).collect();
        let label = format!(
            "{} [{}{}, priority {}]",
            policy.id,
            policy.scope.kind(),
            policy
                .scope
                .value()
                .map(|v| format!(" {v}"))
                .unwrap_or_default(),
            policy.priority
        );
        if policy.dry_run {
            explanation.push(format!(
                "{label} matched (dry run, not applied): would {}",
                summary.join(", ")
            ));
            continue;
        }
        explanation.push(format!("{label} matched: {}", summary.join(", ")));
        for action in &policy.actions {
            if action.is_terminal() {
                if verdict.is_none() {
                    verdict = Some(to_verdict(action, &policy.id));
                    actions.push(action.clone());
                }
            } else {
                actions.push(action.clone());
            }
        }
    }
    let mut verdict = verdict.unwrap_or_else(|| {
        explanation.push("no policy set a verdict: deliver".into());
        Verdict::Deliver
    });
    // Never deliver mail a required scanner did not see, whatever the policy says.
    if verdict == Verdict::Deliver && signals.flags.contains("defer") {
        explanation.push("required scanner unreachable: defer instead of deliver".into());
        verdict = Verdict::Defer {
            reason: "required scanner unreachable".into(),
        };
    }
    Decision {
        recipient: ctx.recipient.to_string(),
        verdict,
        actions,
        matched,
        explanation,
    }
}

/// Envelope facts for a whole message.
#[derive(Debug, Clone, Copy)]
pub struct Message<'a> {
    pub tenant_id: Option<&'a str>,
    pub direction: Direction,
    pub sender: &'a str,
    pub recipients: &'a [String],
}

/// One decision per recipient. A message without recipients still gets one
/// decision, for an empty recipient, so it is never left undecided.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageDecision {
    pub decisions: Vec<Decision>,
}

pub fn evaluate_message(report: &ScanReport, msg: &Message, set: &PolicySet) -> MessageDecision {
    evaluate_signals(&Signals::from_report(report), msg, set)
}

pub fn evaluate_signals(signals: &Signals, msg: &Message, set: &PolicySet) -> MessageDecision {
    let empty = [String::new()];
    let recipients = if msg.recipients.is_empty() {
        &empty[..]
    } else {
        msg.recipients
    };
    let decisions = recipients
        .iter()
        .map(|recipient| {
            let ctx = Context {
                tenant_id: msg.tenant_id,
                direction: msg.direction,
                sender: msg.sender,
                recipient,
            };
            evaluate(signals, &ctx, set)
        })
        .collect();
    MessageDecision { decisions }
}

impl MessageDecision {
    /// Recipients grouped by identical verdict and actions. More than one group
    /// means the message has to be split.
    pub fn split(&self) -> Vec<Vec<&Decision>> {
        let mut groups: Vec<Vec<&Decision>> = Vec::new();
        for decision in &self.decisions {
            match groups.iter_mut().find(|group| {
                group[0].verdict == decision.verdict && group[0].actions == decision.actions
            }) {
                Some(group) => group.push(decision),
                None => groups.push(vec![decision]),
            }
        }
        groups
    }

    /// One verdict for callers that do not split: the shared verdict, or the
    /// one that holds the message rather than losing or releasing it.
    pub fn verdict(&self) -> Verdict {
        let rank = |v: &Verdict| match v {
            Verdict::Quarantine { .. } => 4,
            Verdict::Reject { .. } => 3,
            Verdict::Defer { .. } => 2,
            Verdict::Discard => 1,
            Verdict::Deliver => 0,
        };
        self.decisions
            .iter()
            .map(|d| &d.verdict)
            .max_by_key(|v| rank(v))
            .cloned()
            .unwrap_or(Verdict::Deliver)
    }
}

fn applies(policy: &Policy, ctx: &Context, set: &PolicySet) -> bool {
    if let Some(tenant) = &policy.tenant_id {
        if ctx.tenant_id != Some(tenant.as_str()) {
            return false;
        }
    }
    // Scope means our side of the conversation.
    let party = match ctx.direction {
        Direction::Inbound => ctx.recipient,
        Direction::Outbound => ctx.sender,
    };
    match &policy.scope {
        Scope::Global | Scope::Tenant => true,
        Scope::Domain(domain) => domain_of(party).eq_ignore_ascii_case(domain),
        Scope::Group(group) => set.in_group(group, party),
        Scope::User(user) => party.eq_ignore_ascii_case(user),
    }
}

fn holds(condition: &Condition, signals: &Signals, ctx: &Context, set: &PolicySet) -> bool {
    match condition {
        Condition::Direction(flow) => Flow::from(ctx.direction) == *flow,
        Condition::Sender(pattern) => address_matches(pattern, ctx.sender),
        Condition::Recipient(pattern) => address_matches(pattern, ctx.recipient),
        Condition::Group(group) => set.in_group(group, ctx.recipient),
        Condition::Flag(name) => signals.flags.contains(name),
        Condition::Score {
            name,
            at_least,
            below,
        } => signals.scores.get(name).is_some_and(|score| {
            at_least.is_none_or(|min| *score >= min) && below.is_none_or(|max| *score < max)
        }),
        Condition::Count { name, at_least } => {
            signals.counts.get(name).copied().unwrap_or(0) >= *at_least
        }
        Condition::Marking(marking) => match &signals.marking {
            Some(found) => found.eq_ignore_ascii_case(marking),
            None => marking.eq_ignore_ascii_case("none"),
        },
        Condition::Auth { method, result } => signals
            .auth_result(method)
            .iter()
            .any(|found| found.eq_ignore_ascii_case(result)),
    }
}

fn address_matches(pattern: &str, address: &str) -> bool {
    let pattern = pattern.trim();
    if pattern == "*" {
        return true;
    }
    match pattern
        .strip_prefix("*@")
        .or_else(|| pattern.strip_prefix('@'))
    {
        Some(domain) => domain_of(address).eq_ignore_ascii_case(domain),
        None => pattern.eq_ignore_ascii_case(address),
    }
}

fn domain_of(address: &str) -> &str {
    address.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
}

fn to_verdict(action: &Action, id: &str) -> Verdict {
    match action {
        Action::Quarantine(_) => Verdict::Quarantine { reason: id.into() },
        Action::Reject { code } => Verdict::Reject {
            code: *code,
            reason: id.into(),
        },
        Action::Discard => Verdict::Discard,
        Action::Defer => Verdict::Defer { reason: id.into() },
        _ => Verdict::Deliver,
    }
}

fn describe(action: &Action) -> String {
    match action {
        Action::Deliver => "deliver".into(),
        Action::Quarantine(queue) => format!("quarantine to {queue}"),
        Action::Reject { code } => format!("reject {code}"),
        Action::Discard => "discard".into(),
        Action::Defer => "defer".into(),
        Action::AddHeader { name, value } => format!("add header {name}: {value}"),
        Action::Banner(_) => "add banner".into(),
        Action::Redirect(to) => format!("redirect to {to}"),
        Action::Bcc(to) => format!("bcc {to}"),
        Action::Encrypt => "encrypt".into(),
        Action::RequireTls => "require TLS".into(),
    }
}
