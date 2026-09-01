"""
Canonical domain and result models for the policy-activation.v1 kernel.

This module defines:
- State
- Event
- TransitionResult
- helpers for computing ActualEffects(previous_state, next_state)

It is deliberately minimal and dependency-free.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Core domain models
# ---------------------------------------------------------------------------

@dataclass
class NodeState:
    state: str
    local_activation: Optional[Dict[str, Any]] = None
    seen_event_ids: Set[str] = field(default_factory=set)
    activation_identities: Set[Tuple[str, int, int, str]] = field(default_factory=set)
    quarantine_state: bool = False


@dataclass
class GlobalState:
    authoritative_activation: Optional[Dict[str, Any]] = None
    node: NodeState = field(default_factory=lambda: NodeState(state="UNINITIALIZED"))


@dataclass
class Event:
    type: str
    payload: Dict[str, Any]


@dataclass
class TransitionResult:
    transition_id: Optional[str]
    decision: str
    previous_state: GlobalState
    next_state: GlobalState
    effects_applied: List[str]
    invariants_checked: List[str]
    invariant_results: Dict[str, bool]
    telemetry_requirements: List[str]


# ---------------------------------------------------------------------------
# Effect diffing (ActualEffects)
# ---------------------------------------------------------------------------

def compute_actual_effects(previous: GlobalState, next_: GlobalState) -> Set[str]:
    """
    Compute a coarse-grained set of mutations between previous_state and next_state.

    This is intentionally simple: it maps structural changes to canonical effect labels.
    The semantic_validator + reference_engine enforce that this set is:
      - a subset of DeclaredEffects(transition)
      - disjoint from ForbiddenEffects(transition)
    """
    effects: Set[str] = set()

    # Node state changes
    if previous.node.state != next_.node.state:
        if next_.node.state == "UNINITIALIZED":
            effects.add("set_state_uninitialized")
        elif next_.node.state == "PENDING_VERIFICATION":
            effects.add("set_state_pending_verification")
        elif next_.node.state == "STAGED":
            effects.add("set_state_staged")
        elif next_.node.state == "ACTIVE":
            effects.add("set_state_active")
        elif next_.node.state == "QUARANTINED":
            effects.add("set_state_quarantined")
        elif next_.node.state == "RECONCILING":
            effects.add("set_state_reconciling")

    if previous.node.quarantine_state != next_.node.quarantine_state:
        if next_.node.quarantine_state:
            effects.add("set_quarantine_true")

    # Seen event IDs
    if previous.node.seen_event_ids != next_.node.seen_event_ids:
        effects.add("record_event_observation")

    # Activation identities
    if previous.node.activation_identities != next_.node.activation_identities:
        effects.add("record_effective_activation")

    # Local activation
    if previous.node.local_activation != next_.node.local_activation:
        # Distinguish authority vs candidate via context in engine
        effects.add("set_active_activation")

    # Authoritative activation
    if previous.authoritative_activation != next_.authoritative_activation:
        effects.add("modify_authoritative_activation")

    return effects
