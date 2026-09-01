"""
Closed vocabularies for the policy-activation.v1 kernel.

This file defines the canonical sets of:
- STATES
- EVENTS
- DECISIONS
- EFFECTS
- INVARIANTS

These vocabularies must match policy-activation.v1.json exactly.
No runtime may introduce new members.
"""

# ---------------------------------------------------------------------------
# STATES
# ---------------------------------------------------------------------------

STATES = {
    "UNINITIALIZED",
    "PENDING_VERIFICATION",
    "STAGED",
    "ACTIVE",
    "QUARANTINED",
    "RECONCILING",
}

# ---------------------------------------------------------------------------
# EVENTS
# ---------------------------------------------------------------------------

EVENTS = {
    "AUTHORITATIVE_ACTIVATION_OBSERVED",
    "EVENT_RECEIVED",
    "VERIFICATION_SUCCEEDED",
    "VERIFICATION_FAILED",
    "RECONCILIATION_REQUESTED",
    "RECONCILIATION_SUCCEEDED",
    "QUARANTINE_REQUESTED",
}

# ---------------------------------------------------------------------------
# DECISIONS (canonical result algebra)
# ---------------------------------------------------------------------------

DECISIONS = {
    "TRANSITION",
    "NOOP",
    "AMBIGUITY_FAILURE",
    "GUARD_FAILURE",
    "EFFECT_FAILURE",
    "INVARIANT_FAILURE",
    "VALIDATION_FAILURE",
}

# ---------------------------------------------------------------------------
# EFFECTS (closed effect vocabulary)
# ---------------------------------------------------------------------------

EFFECTS = {
    "record_event_observation",
    "set_state_uninitialized",
    "set_state_pending_verification",
    "set_state_staged",
    "set_state_active",
    "set_state_quarantined",
    "set_state_reconciling",
    "set_quarantine_true",
    "set_candidate_activation_tuple",
    "set_active_activation",
    "set_active_activation_to_authority",
    "record_effective_activation",
    "emit_activation_decision",

    # Forbidden-effect vocabulary (must remain closed)
    "modify_authoritative_activation",
    "activate_different_tuple",
    "create_duplicate_effective_activation",
}

# ---------------------------------------------------------------------------
# INVARIANTS
# ---------------------------------------------------------------------------

INVARIANTS = {
    "I1_TELEMETRY_IMMUTABILITY",
    "I2_EVENT_IDENTITY_AND_PAYLOAD_INTEGRITY",

    "P1_ARTIFACT_IMMUTABILITY",
    "P2_AUTHORITATIVE_EPOCH_ORDERING",
    "P3_IDENTIFIER_SEPARATION",

    "N1_NO_UNVERIFIED_ACTIVATION",
    "N2_STALE_DELIVERY_NOT_INTEGRITY_FAILURE",
    "N3_IDEMPOTENT_EFFECTIVE_TRANSITIONS",

    "C1_EPOCH_SCOPED_CONVERGENCE_MEMBERSHIP",
    "C2_AUTHORITATIVE_RECONCILIATION",
    "C3_INTENT_ADOPTION_INDEPENDENCE",

    "S1_TRANSITION_CLOSURE",
    "S2_EFFECT_CLOSURE",
    "S3_TOTAL_OBSERVABILITY",
}

# ---------------------------------------------------------------------------
# VALIDATION HELPERS
# ---------------------------------------------------------------------------

def is_valid_state(value: str) -> bool:
    return value in STATES

def is_valid_event(value: str) -> bool:
    return value in EVENTS

def is_valid_decision(value: str) -> bool:
    return value in DECISIONS

def is_valid_effect(value: str) -> bool:
    return value in EFFECTS

def is_valid_invariant(value: str) -> bool:
    return value in INVARIANTS
