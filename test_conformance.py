"""
Conformance test suite for the policy-activation.v1 kernel.

Runs deterministic vectors through the reference engine and asserts
canonical byte-for-byte reproducibility of observable results.
"""

import json
import unittest

from model import GlobalState, NodeState, Event
from reference_engine import resolve
from canonical import canonical_serialize


class KernelConformanceTest(unittest.TestCase):
    def setUp(self) -> None:
        with open("vectors.json", "r", encoding="utf-8") as f:
            data = json.load(f)
        self.vectors = data["vectors"]

    def _build_state(self, raw: dict) -> GlobalState:
        node_raw = raw["node"]
        node = NodeState(
            state=node_raw["state"],
            local_activation=node_raw.get("local_activation"),
            seen_event_ids=set(node_raw.get("seen_event_ids", [])),
            activation_identities=set(
                tuple(x) for x in node_raw.get("activation_identities", [])
            ),
            quarantine_state=node_raw.get("quarantine_state", False),
        )
        return GlobalState(
            authoritative_activation=raw.get("authoritative_activation"),
            node=node,
        )

    def _build_event(self, raw: dict) -> Event:
        return Event(type=raw["type"], payload=raw["payload"])

    def test_vectors(self):
        for vector in self.vectors:
            with self.subTest(vector_id=vector["id"]):
                spec = vector["specification"]
                previous_state = self._build_state(vector["previous_state"])
                event = self._build_event(vector["event"])

                result = resolve(spec, previous_state, event)

                # Canonical observable projection
                observed = {
                    "transition_id": result.transition_id,
                    "decision": result.decision,
                    "effects_applied": result.effects_applied,
                }

                expected = vector["expected_result"]

                self.assertEqual(
                    canonical_serialize(observed),
                    canonical_serialize(expected),
                    msg=f"Vector {vector['id']} failed canonical comparison",
                )


if __name__ == "__main__":
    unittest.main()
