"""
Reference execution engine for the policy-activation.v1 kernel.

Implements:
- deterministic transition resolution (S1)
- guard evaluation
- effect application
- forbidden-effect rejection (S2)
- invariant evaluation
- total observability (S3)

Every invocation returns exactly one TransitionResult.
"""

from typing import Dict, Any, List, Optional
from vocabulary import STATES, EVENTS, DECISIONS, EFFECTS
from model import GlobalState, Event, TransitionResult, compute_actual_effects
from invariant_evaluator import evaluate_invariants


# ---------------------------------------------------------------------------
# Utility: deep copy
# ---------------------------------------------------------------------------

import copy

def deep_copy_state(state: GlobalState) -> GlobalState:
    return copy.deepcopy(state)


# ---------------------------------------------------------------------------
# Guard evaluation (minimal DSL)
# ---------------------------------------------------------------------------

def eval_guard(guard: str, state: GlobalState, event: Event) -> bool:
    """
    Minimal guard evaluator.

    Guards are simple Python expressions referencing:
      - event
      - node
      - authoritative_activation

    This is safe because the kernel is dependency-free and guards come from
    the canonical specification only.
    """
    try:
        node = state.node
        authoritative_activation = state.authoritative_activation
        return bool(eval(guard, {}, {
            "event": event.payload,
            "node": node,
            "authoritative_activation": authoritative_activation
        }))
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Effect application
# ---------------------------------------------------------------------------

def apply_effect(state: GlobalState, effect: str, event: Event) -> GlobalState:
    """
    Apply a declared effect to the state.
    Effects are pure, deterministic, and closed.
    """
    new = deep_copy_state(state)

    if effect == "record_event_observation":
        new.node.seen_event_ids.add(event.payload.get("event_id"))

    elif effect == "set_state_uninitialized":
        new.node.state = "UNINITIALIZED"

    elif effect == "set_state_pending_verification":
        new.node.state = "PENDING_VERIFICATION"

    elif effect == "set_state_staged":
        new.node.state = "STAGED"

    elif effect == "set_state_active":
        new.node.state = "ACTIVE"

    elif effect == "set_state_quarantined":
        new.node.state = "QUARANTINED"

    elif effect == "set_state_reconciling":
        new.node.state = "RECONCILING"

    elif effect == "set_quarantine_true":
        new.node.quarantine_state = True

    elif effect == "set_candidate_activation_tuple":
        new.node.local_activation = event.payload.get("candidate_activation")

    elif effect == "set_active_activation":
        new.node.local_activation = event.payload.get("candidate_activation")

    elif effect == "set_active_activation_to_authority":
        new.node.local_activation = new.authoritative_activation

    elif effect == "record_effective_activation":
        tup = event.payload.get("candidate_activation")
        if tup:
            new.node.activation_identities.add(tuple(tup.values()))

    elif effect == "modify_authoritative_activation":
        new.authoritative_activation = event.payload.get("authoritative_activation")

    elif effect == "emit_activation_decision":
        # No-op placeholder: telemetry is external
        pass

    return new


# ---------------------------------------------------------------------------
# Transition resolution
# ---------------------------------------------------------------------------

def resolve(spec: Dict[str, Any], state: GlobalState, event: Event) -> TransitionResult:
    """
    Resolve and execute a transition according to the canonical kernel rules.

    Always returns exactly one TransitionResult (S3_TOTAL_OBSERVABILITY).
    """

    previous = deep_copy_state(state)

    # Identify enabled transitions
    enabled = []
    for t in spec["transitions"]:
        if state.node.state in t["from"] and event.type == t["event"]:
            # Evaluate guards
            if all(eval_guard(g, state, event) for g in t["guards"]):
                enabled.append(t)

    # NOOP
    if len(enabled) == 0:
        return TransitionResult(
            transition_id=None,
            decision="NOOP",
            previous_state=previous,
            next_state=previous,
            effects_applied=[],
            invariants_checked=[],
            invariant_results={},
            telemetry_requirements=["TRANSITION_NOOP"]
        )

    # Ambiguity failure
    if len(enabled) > 1:
        return TransitionResult(
            transition_id=None,
            decision="AMBIGUITY_FAILURE",
            previous_state=previous,
            next_state=previous,
            effects_applied=[],
            invariants_checked=[],
            invariant_results={},
            telemetry_requirements=["AMBIGUITY_DETECTED"]
        )

    # Execute the single transition
    t = enabled[0]
    next_state = deep_copy_state(state)
    applied_effects: List[str] = []

    # Apply declared effects
    for eff in t["effects"]:
        next_state = apply_effect(next_state, eff, event)
        applied_effects.append(eff)

    # Compute actual effects
    actual = compute_actual_effects(previous, next_state)

    # Effect closure violation
    if not actual.issubset(set(t["effects"])):
        return TransitionResult(
            transition_id=t["id"],
            decision="EFFECT_FAILURE",
            previous_state=previous,
            next_state=previous,
            effects_applied=[],
            invariants_checked=[],
            invariant_results={},
            telemetry_requirements=["EFFECT_CLOSURE_VIOLATION"]
        )

    # Forbidden effects violation
    forbidden = set(t["forbidden_effects"])
    if actual.intersection(forbidden):
        return TransitionResult(
            transition_id=t["id"],
            decision="EFFECT_FAILURE",
            previous_state=previous,
            next_state=previous,
            effects_applied=[],
            invariants_checked=[],
            invariant_results={},
            telemetry_requirements=["FORBIDDEN_EFFECT_VIOLATION"]
        )

    # Invariant evaluation
    invariant_results = evaluate_invariants(
        previous_state=previous,
        event=event,
        next_state=next_state,
        transition_id=t["id"],
        invariant_ids=t["invariants"]
    )

    if not all(invariant_results.values()):
        return TransitionResult(
            transition_id=t["id"],
            decision="INVARIANT_FAILURE",
            previous_state=previous,
            next_state=previous,
            effects_applied=[],
            invariants_checked=t["invariants"],
            invariant_results=invariant_results,
            telemetry_requirements=["INVARIANT_VIOLATION"]
        )

    # Successful transition
    return TransitionResult(
        transition_id=t["id"],
        decision="TRANSITION",
        previous_state=previous,
        next_state=next_state,
        effects_applied=applied_effects,
        invariants_checked=t["invariants"],
        invariant_results=invariant_results,
        telemetry_requirements=["TRANSITION_SUCCESS"]
    )
