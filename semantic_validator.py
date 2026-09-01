"""
Semantic validator for the policy-activation.v1 kernel.

This validator enforces:
- V1 TRANSITION_CLOSURE
- V2 DETERMINISTIC_RESOLUTION
- V3 EFFECT_ACCOUNTABILITY
- S1 TRANSITION_CLOSURE
- S2 EFFECT_CLOSURE
- S3 TOTAL_OBSERVABILITY (checked in engine)

It ensures the specification is internally coherent BEFORE execution.
"""

from typing import Dict, Any, List, Set
from vocabulary import STATES, EVENTS, DECISIONS, EFFECTS, INVARIANTS


# ---------------------------------------------------------------------------
# Validation errors
# ---------------------------------------------------------------------------

class SpecValidationError(Exception):
    pass


# ---------------------------------------------------------------------------
# Core validator
# ---------------------------------------------------------------------------

def validate_representation(spec: Dict[str, Any]) -> None:
    """
    Structural validation beyond schema.json.
    Ensures vocabularies match the closed kernel.
    """

    # Validate states
    for s in spec["states"]:
        if s not in STATES:
            raise SpecValidationError(f"UNKNOWN_STATE: {s}")

    # Validate events
    for e in spec["events"]:
        if e not in EVENTS:
            raise SpecValidationError(f"UNKNOWN_EVENT: {e}")

    # Validate decisions
    for d in spec["decisions"]:
        if d not in DECISIONS:
            raise SpecValidationError(f"UNKNOWN_DECISION: {d}")

    # Validate effects
    for eff in spec["effects"]:
        if eff not in EFFECTS:
            raise SpecValidationError(f"UNKNOWN_EFFECT: {eff}")

    # Validate invariants
    for inv in spec["invariants"].keys():
        if inv not in INVARIANTS:
            raise SpecValidationError(f"UNKNOWN_INVARIANT: {inv}")


def validate_semantics(spec: Dict[str, Any]) -> None:
    """
    Semantic coherence validation.
    Ensures transitions are deterministic, closed, and non-ambiguous.
    """

    transition_ids: Set[str] = set()

    for t in spec["transitions"]:
        tid = t["id"]

        # Duplicate transition ID
        if tid in transition_ids:
            raise SpecValidationError(f"DUPLICATE_TRANSITION_ID: {tid}")
        transition_ids.add(tid)

        # Validate FROM states
        for s in t["from"]:
            if s not in STATES:
                raise SpecValidationError(f"INVALID_TRANSITION_REFERENCE: state {s}")

        # Validate event
        if t["event"] not in EVENTS:
            raise SpecValidationError(f"INVALID_TRANSITION_REFERENCE: event {t['event']}")

        # Validate effects
        for eff in t["effects"]:
            if eff not in EFFECTS:
                raise SpecValidationError(f"UNKNOWN_EFFECT: {eff}")

        # Validate forbidden effects
        for feff in t["forbidden_effects"]:
            if feff not in EFFECTS:
                raise SpecValidationError(f"UNKNOWN_FORBIDDEN_EFFECT: {feff}")

        # Self-forbidden effect
        for eff in t["effects"]:
            if eff in t["forbidden_effects"]:
                raise SpecValidationError(f"EFFECT_FORBIDDEN_BY_SELF: {tid} -> {eff}")

        # Validate invariants
        for inv in t["invariants"]:
            if inv not in INVARIANTS:
                raise SpecValidationError(f"UNKNOWN_INVARIANT: {inv}")

    # Deterministic resolution check (V2)
    _validate_deterministic_resolution(spec)


def _validate_deterministic_resolution(spec: Dict[str, Any]) -> None:
    """
    Ensures that for every (state, event) pair,
    at most one transition is enabled.

    This is a static check: guards are strings, so we only check
    structural ambiguity (multiple transitions with same from+event).
    """

    mapping: Dict[tuple, List[str]] = {}

    for t in spec["transitions"]:
        for s in t["from"]:
            key = (s, t["event"])
            mapping.setdefault(key, []).append(t["id"])

    for (state, event), tids in mapping.items():
        if len(tids) > 1:
            raise SpecValidationError(
                f"AMBIGUOUS_TRANSITION: state={state}, event={event}, transitions={tids}"
            )
