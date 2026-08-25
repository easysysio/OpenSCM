// alerting.rs — trigger semantics.
//
// Design: docs/design/0.9.0-alerting.md §4. These are the rules that decide
// whether people keep alerting switched on. The failure that matters is not
// "missed an alert" but "sent the same alert every minute until it was muted",
// so the edge behaviour is pinned here rather than left to the handlers.

use scmserver::alerts::{evaluate, Decision, Observation, Rule};

fn rule(trigger: &str, threshold: f64) -> Rule {
    Rule {
        id: 1,
        tenant_id: "default".into(),
        name: "test rule".into(),
        scope_type: "policy".into(),
        policy_id: Some(1),
        trigger_type: trigger.into(),
        threshold,
        score_axis: "test".into(),
        action: "notify".into(),
        target: None,
        cooldown_minutes: 60,
    }
}

fn obs(previous: f64, current: f64) -> Observation {
    Observation { previous, current }
}

#[test]
fn drop_fires_only_when_the_fall_reaches_the_threshold() {
    let r = rule("drop", 10.0);
    assert_eq!(evaluate(&r, obs(94.0, 61.0), false), Decision::Fire);
    assert_eq!(evaluate(&r, obs(94.0, 84.0), false), Decision::Fire, "exactly 10 is a fire");
    assert_eq!(evaluate(&r, obs(94.0, 85.0), false), Decision::Quiet, "9 points is not");
    assert_eq!(evaluate(&r, obs(61.0, 94.0), false), Decision::Quiet, "a rise is not a drop");
}

#[test]
fn gain_is_the_mirror_of_drop() {
    let r = rule("gain", 10.0);
    assert_eq!(evaluate(&r, obs(61.0, 94.0), false), Decision::Fire);
    assert_eq!(evaluate(&r, obs(94.0, 61.0), false), Decision::Quiet);
}

// The one that decides whether alerting stays enabled: a policy resting below
// the threshold must not re-alert on every recalculation.
#[test]
fn below_fires_on_the_crossing_and_then_stays_quiet() {
    let r = rule("below", 80.0);
    assert_eq!(evaluate(&r, obs(85.0, 79.0), false), Decision::Fire, "crossed downward");
    assert_eq!(evaluate(&r, obs(79.0, 78.0), false), Decision::Quiet, "already below — no repeat");
    assert_eq!(evaluate(&r, obs(78.0, 60.0), false), Decision::Quiet, "still below, falling further");
}

#[test]
fn below_rearms_once_the_score_recovers() {
    let r = rule("below", 80.0);
    assert_eq!(evaluate(&r, obs(70.0, 85.0), false), Decision::Quiet, "recovering is not a fire");
    assert_eq!(evaluate(&r, obs(85.0, 70.0), false), Decision::Fire, "and now it can fire again");
}

#[test]
fn above_is_the_mirror_of_below() {
    let r = rule("above", 90.0);
    assert_eq!(evaluate(&r, obs(85.0, 95.0), false), Decision::Fire);
    assert_eq!(evaluate(&r, obs(95.0, 97.0), false), Decision::Quiet, "already above");
}

// -1 means "never scanned", not zero. Treating it as a score turns a
// bookkeeping change into a 95-point drop at 03:00.
#[test]
fn never_scanned_is_not_a_score() {
    let r = rule("drop", 10.0);
    assert_eq!(evaluate(&r, obs(95.0, -1.0), false), Decision::NoComparison,
               "a policy going unscanned is not a 96-point drop");
    assert_eq!(evaluate(&r, obs(-1.0, 40.0), false), Decision::NoComparison,
               "a first scan has nothing to compare against");
    assert_eq!(evaluate(&r, obs(-1.0, -1.0), false), Decision::NoComparison);
}

// Muted is distinct from Quiet on purpose: a muted evaluation still has to
// advance the stored baseline, or the cooldown expires against a stale score.
#[test]
fn cooldown_mutes_rather_than_silences() {
    let r = rule("drop", 10.0);
    assert_eq!(evaluate(&r, obs(94.0, 61.0), true), Decision::Muted);
    assert_eq!(evaluate(&r, obs(94.0, 93.0), true), Decision::Quiet,
               "inside cooldown, a non-event is still a non-event");
}

#[test]
fn an_unknown_trigger_never_fires() {
    let r = rule("sideways", 10.0);
    assert_eq!(evaluate(&r, obs(94.0, 10.0), false), Decision::Quiet);
}

// An all_policies rule watches everything; a scoped one watches exactly one.
#[test]
fn scope_selects_the_right_policies() {
    use scmserver::alerts::applies_to;
    let mut r = rule("drop", 10.0);
    assert!(applies_to(&r, 1));
    assert!(!applies_to(&r, 2), "a policy-scoped rule must not watch other policies");

    r.scope_type = "all_policies".into();
    r.policy_id = None;
    assert!(applies_to(&r, 1) && applies_to(&r, 999));
}
