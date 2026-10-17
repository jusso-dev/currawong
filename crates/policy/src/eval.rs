//! Deterministic evaluation.
//!
//! 1. The built-in floor runs first and is not part of any pack: malware is
//!    quarantined, a deferred scan is deferred, a failed scan is quarantined.
//!    Only a matching platform global policy with `override_floor` lifts it.
//! 2. Policies run most specific scope first, then by priority (lower first),
//!    then by tenant and id. The first matching policy with a terminal action
//!    sets the verdict; non-terminal actions from matching policies up to then
//!    are kept, and mandatory policies add theirs afterwards too.
//! 3. Dry-run policies are explained only.
use crate::model::{
    canonical_address, canonical_domain, canonical_pattern, Action, Condition, Flow, Policy,
    PolicySet, Scope,
};
use crate::signals::Signals;
use currawong_core::{Direction, ScanReport, Verdict};
use serde::{Deserialize, Serialize};

/// One recipient being decided. A message can span tenants and directions,
/// so both are resolved per recipient.
#[derive(Debug, Clone, Copy)]
pub struct Context<'a> {
    pub tenant_id: Option<&'a str>,
    /// Inbound: scope by recipient. Outbound: scope by sender.
    pub direction: Direction,
    pub sender: &'a str,
    /// Authenticated submission identity. Outbound user and group scopes match
    /// only this, never the unauthenticated MAIL FROM.
    pub sender_identity: Option<&'a str>,
    pub recipient: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Matched {
    pub id: String,
    pub dry_run: bool,
}

/// The outcome for one recipient.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Decision {
    pub recipient: String,
    pub tenant_id: Option<String>,
    pub verdict: Verdict,
    /// Every action that took effect, terminal one included, in order.
    pub actions: Vec<Action>,
    /// Per action: it came from the floor, a platform policy or a mandatory
    /// policy, so a sender-controlled signal must never skip it.
    pub enforced: Vec<bool>,
    pub matched: Vec<Matched>,
    pub explanation: Vec<String>,
}

impl Decision {
    /// Quarantine queue named by the terminal action, if any.
    pub fn queue(&self) -> Option<&str> {
        self.actions.iter().find_map(|action| match action {
            Action::Quarantine(queue) => Some(queue.as_str()),
            _ => None,
        })
    }
}

/// Flag, rule id (see `FLOOR_RULES`) and queue. Order matters: malware wins
/// over a deferred scan.
const FLOOR: [(&str, &str, Option<&str>); 3] = [
    ("malware", "malware", Some("malware")),
    ("defer", "scan-deferred", None),
    ("fail_closed", "scan-failed", Some("scan-failed")),
];

pub fn evaluate(signals: &Signals, ctx: &Context, set: &PolicySet) -> Decision {
    evaluate_ordered(signals, ctx, set, &ordered(set))
}

fn ordered(set: &PolicySet) -> Vec<&Policy> {
    let mut order: Vec<&Policy> = set.policies.iter().filter(|p| p.enabled).collect();
    order.sort_by(|a, b| {
        b.scope
            .specificity()
            .cmp(&a.scope.specificity())
            .then(a.priority.cmp(&b.priority))
            .then(a.tenant_id.cmp(&b.tenant_id))
            .then(a.id.cmp(&b.id))
    });
    order
}

fn evaluate_ordered(
    signals: &Signals,
    ctx: &Context,
    set: &PolicySet,
    order: &[&Policy],
) -> Decision {
    let mut verdict = None;
    let mut actions = Vec::new();
    let mut enforced = Vec::new();
    let mut matched = Vec::new();
    let mut explanation = Vec::new();
    let matches = |policy: &Policy| {
        applies(policy, ctx, set)
            && policy
                .conditions
                .iter()
                .all(|c| holds(c, policy, signals, ctx, set))
    };

    // Each set floor rule applies unless a platform policy lifts that rule.
    for (flag, rule, queue) in FLOOR {
        if !signals.flags.contains(flag) {
            continue;
        }
        let lifted = order.iter().find(|p| {
            p.override_floor.iter().any(|r| r == rule)
                && !p.dry_run
                && p.tenant_id.is_none()
                && p.scope == Scope::Global
                && matches(p)
        });
        if let Some(policy) = lifted {
            explanation.push(format!("floor {rule} lifted by {}", policy.id));
            continue;
        }
        let action = match queue {
            Some(queue) => Action::Quarantine(queue.to_string()),
            None => Action::Defer,
        };
        explanation.push(format!("floor {rule} matched: {}", describe(&action)));
        matched.push(Matched {
            id: format!("floor:{rule}"),
            dry_run: false,
        });
        verdict = Some(to_verdict(&action, rule));
        actions.push(action);
        enforced.push(true);
        break;
    }

    for policy in order {
        // Once decided, only dry-run (to report) and mandatory (for their
        // non-terminal actions) policies are still looked at.
        if verdict.is_some() && !policy.dry_run && !policy.mandatory {
            continue;
        }
        if !matches(policy) {
            continue;
        }
        matched.push(Matched {
            id: policy.id.clone(),
            dry_run: policy.dry_run,
        });
        let summary: Vec<String> = policy.actions.iter().map(describe).collect();
        let label = format!(
            "{} [{}{}{}, priority {}]",
            policy.id,
            policy
                .tenant_id
                .as_deref()
                .map(|t| format!("tenant {t}, "))
                .unwrap_or_default(),
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
        let enforce = policy.mandatory || policy.tenant_id.is_none();
        for action in &policy.actions {
            if !action.is_terminal() {
                actions.push(action.clone());
                enforced.push(enforce);
            } else if verdict.is_none() {
                verdict = Some(to_verdict(action, &policy.id));
                actions.push(action.clone());
                enforced.push(enforce);
            }
        }
    }
    let verdict = verdict.unwrap_or_else(|| {
        explanation.push("no policy set a verdict: deliver".into());
        Verdict::Deliver
    });
    Decision {
        recipient: ctx.recipient.to_string(),
        tenant_id: ctx.tenant_id.map(str::to_string),
        verdict,
        actions,
        enforced,
        matched,
        explanation,
    }
}

/// One decision per context, in order.
#[derive(Debug, Clone, PartialEq)]
pub struct MessageDecision {
    pub decisions: Vec<Decision>,
}

pub fn evaluate_message(
    report: &ScanReport,
    recipients: &[Context],
    set: &PolicySet,
) -> MessageDecision {
    evaluate_signals(&Signals::from_report(report), recipients, set)
}

pub fn evaluate_signals(
    signals: &Signals,
    recipients: &[Context],
    set: &PolicySet,
) -> MessageDecision {
    let order = ordered(set);
    MessageDecision {
        decisions: recipients
            .iter()
            .map(|ctx| evaluate_ordered(signals, ctx, set, &order))
            .collect(),
    }
}

impl MessageDecision {
    /// Recipients grouped by identical tenant, verdict and actions. More than
    /// one group means the message has to be split.
    pub fn split(&self) -> Vec<Vec<&Decision>> {
        let mut groups: Vec<Vec<&Decision>> = Vec::new();
        for decision in &self.decisions {
            match groups.iter_mut().find(|group| {
                group[0].tenant_id == decision.tenant_id
                    && group[0].verdict == decision.verdict
                    && group[0].actions == decision.actions
                    && group[0].enforced == decision.enforced
            }) {
                Some(group) => group.push(decision),
                None => groups.push(vec![decision]),
            }
        }
        groups
    }

    /// One verdict for callers that do not split: hold rather than release,
    /// and never let one recipient's discard drop everyone's mail.
    pub fn verdict(&self) -> Verdict {
        let rank = |v: &Verdict| match v {
            Verdict::Quarantine { .. } => 4,
            Verdict::Reject { .. } => 3,
            Verdict::Defer { .. } => 2,
            Verdict::Deliver => 1,
            Verdict::Discard => 0,
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
    let owner = policy.tenant_id.as_deref();
    match (&policy.scope, ctx.direction) {
        (Scope::Global | Scope::Tenant, _) => true,
        (Scope::Domain(domain), Direction::Inbound) => {
            domain_of(ctx.recipient) == canonical_domain(domain)
        }
        (Scope::Group(group), Direction::Inbound) => set.in_group(owner, group, ctx.recipient),
        (Scope::User(user), Direction::Inbound) => {
            canonical_address(ctx.recipient) == canonical_pattern(user)
        }
        // Outbound: the submission service checks the sender domain belongs to
        // the tenant, but not the mailbox, so user and group need the login.
        (Scope::Domain(domain), Direction::Outbound) => {
            domain_of(ctx.sender_identity.unwrap_or(ctx.sender)) == canonical_domain(domain)
        }
        (Scope::Group(group), Direction::Outbound) => ctx
            .sender_identity
            .is_some_and(|id| set.in_group(owner, group, id)),
        (Scope::User(user), Direction::Outbound) => ctx
            .sender_identity
            .is_some_and(|id| canonical_address(id) == canonical_pattern(user)),
    }
}

fn holds(
    condition: &Condition,
    policy: &Policy,
    signals: &Signals,
    ctx: &Context,
    set: &PolicySet,
) -> bool {
    match condition {
        Condition::Direction(flow) => Flow::from(ctx.direction) == *flow,
        Condition::Sender(pattern) => address_matches(pattern, ctx.sender),
        Condition::Recipient(pattern) => address_matches(pattern, ctx.recipient),
        Condition::Group(group) => set.in_group(policy.tenant_id.as_deref(), group, ctx.recipient),
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
        Some(domain) => domain_of(address) == canonical_domain(domain),
        None => canonical_pattern(pattern) == canonical_address(address),
    }
}

fn domain_of(address: &str) -> String {
    address
        .rsplit_once('@')
        .map(|(_, d)| canonical_domain(d))
        .unwrap_or_default()
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
        Action::EncryptSmime => "encrypt with S/MIME".into(),
        Action::EncryptPortal => "encrypt to the portal".into(),
        Action::RequireTls => "require TLS".into(),
        Action::RequireDane => "require DANE".into(),
    }
}
