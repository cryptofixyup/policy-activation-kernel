"""
Canonical domain and result models for the policy-activation.v1 kernel.

This module defines:
- GlobalState
- NodeState
- Event
- TransitionResult
- ActualEffects(previous_state, next_state)

It is deliberately minimal and dependency-free.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# Core domain models
# ---------------------------------------------------------------------------

@dataclass
class NodeState:
    """
    Canonical node-level state.
    """
    state: str
    local_activation: Optional[Dict[str, Any]] = None
    seen_event_ids: Set[str] = field(default_factory=set)
    activation_identities: Set[Tuple[str, int, int, str]] = field(default_factory=set)
    quarantine_state: bool = False


@dataclass
class GlobalState:
    """
    Canonical global state.
    """
    authoritative_activation: Optional[Dict[str, Any]] = None
    node: NodeState = field(default_factory=lambda: NodeState(state="UNINITIALIZED"))


@dataclass
class Event:
    """
    Canonical event representation.
    """
    type: str
    payload: Dict[str, Any]


@dataclass
class TransitionResult:
    """
    Canonical result of a reference engine invocation.
    Every invocation must produce exactly one TransitionResult (S3_TOTAL_OBSERVABILITY).
    """
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
    Compute the set of actual mutations between previous_state and next_state.

    This is intentionally coarse-grained and deterministic.
    It maps structural changes to canonical effect labels.

    The reference engine enforces:
      - ActualEffects ⊆ DeclaredEffects(selected_transition)   (S2_EFFECT_CLOSURE)
      - ActualEffects ∩ ForbiddenEffects(selected_transition) = ∅
    """

    effects: Set[str] = set()

    # Node state transitions
    if previous.node.state != next_.node.state:
        mapping = {
            "UNINITIALIZED": "set_state_uninitialized",
            "PENDING_VERIFICATION": "set_state_pending_verification",
            "STAGED": "set_state_staged",
            "ACTIVE": "set_state_active",
            "QUARANTINED": "set_state_quarantined",
            "RECONCILING": "set_state_reconciling",
        }
        if next_.node.state in mapping:
            effects.add(mapping[next_.node.state])

    # Quarantine flag
    if previous.node.quarantine_state != next_.node.quarantine_state:
        if next_.node.quarantine_state:
            effects.add("set_quarantine_true")

    # Seen event IDs
    if previous.node.seen_event_ids != next_.node.seen_event_ids:
        effects.add("record_event_observation")

    # Activation identities
    if previous.node.activation_identities != next_.node.activation_identities:
        effects.add("record_effective_activation")

    # Local activation change
    if previous.node.local_activation != next_.node.local_activation:
        effects.add("set_active_activation")

    # Authoritative activation change
    if previous.authoritative_activation != next_.authoritative_activation:
        effects.add("modify_authoritative_activation")

    return effects
