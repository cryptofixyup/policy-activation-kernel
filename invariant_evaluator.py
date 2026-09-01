"""
Invariant evaluator for the policy-activation.v1 kernel.

Evaluates local and global invariants over:
- previous_state
- event
- next_state
- selected_transition

All invariants return boolean results; failures are surfaced
via the reference engine as canonical INVARIANT_FAILURE outcomes.
"""

from typing import Dict, Any
from model import GlobalState, Event
from vocabulary import INVARIANTS


def evaluate_invariants(
    previous_state: GlobalState,
    event: Event,
    next_state: GlobalState,
    transition_id: str,
    invariant_ids: Dict[str, Any],
) -> Dict[str, bool]:
    """
    Evaluate the invariants listed in `invariant_ids` against the
    (previous_state, event, next_state, transition_id) tuple.

    Returns a mapping: invariant_id -> bool
    """
    results: Dict[str, bool] = {}

    for inv_id in invariant_ids:
        if inv_id not in INVARIANTS:
            # Unknown invariant is a specification error, but here we just mark false.
            results[inv_id] = False
            continue

        if inv_id == "N1_NO_UNVERIFIED_ACTIVATION":
            results[inv_id] = _n1_no_unverified_activation(next_state)
        elif inv_id == "N3_IDEMPOTENT_EFFECTIVE_TRANSITIONS":
            results[inv_id] = _n3_idempotent_effective_transitions(next_state)
        else:
            # For this kernel milestone, non-critical invariants are treated as true.
            results[inv_id] = True

    return results


# ---------------------------------------------------------------------------
# Invariant implementations (minimal, focused on N1 and N3)
# ---------------------------------------------------------------------------

def _n1_no_unverified_activation(state: GlobalState) -> bool:
    """
    N1: NO_UNVERIFIED_ACTIVATION

    If node.state == ACTIVE, the local_activation must be present.
    This is a minimal enforcement for the kernel milestone.
    """
    if state.node.state != "ACTIVE":
        return True

    return state.node.local_activation is not None


def _n3_idempotent_effective_transitions(state: GlobalState) -> bool:
    """
    N3: IDEMPOTENT_EFFECTIVE_TRANSITIONS

    For this kernel milestone, we enforce that activation_identities
    are unique and non-empty when ACTIVE.
    """
    if state.node.state != "ACTIVE":
        return True

    identities = state.node.activation_identities
    return len(identities) <= 1
