import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent
LAMBDA_DIR = PROJECT_ROOT / "lambda_dlp"

sys.path.insert(0, str(LAMBDA_DIR))

import index  # noqa: E402


class TestEnterpriseDLPSanitizer(unittest.TestCase):

    def test_ip_redaction(self):
        self.assertEqual(
            index.sanitize_text(
                "Production database located at 10.0.0.4"
            ),
            "Production database located at [REDACTED_IP]",
        )

    def test_email_redaction(self):
        self.assertEqual(
            index.sanitize_text(
                "Escalate issues to lead-dev@company.internal"
            ),
            "Escalate issues to [REDACTED_EMAIL]",
        )

    def test_key_redaction(self):
        result = index.sanitize_text(
            "OPENAI_API_KEY='sk-proj-prod1234567890'"
        )
        self.assertIn("[REDACTED_SECRET]", result)

    def test_nested_payload_redaction(self):
        payload = {
            "metadata": {
                "operator": "admin@example.com",
                "network": [
                    {
                        "host": "10.0.0.4",
                        "token": (
                            "api_key="
                            "abcdefghijklmnopqrstuvwxyz123456"
                        ),
                    }
                ],
            }
        }

        sanitized = index.sanitize_payload(payload)

        self.assertEqual(
            sanitized["metadata"]["operator"],
            "[REDACTED_EMAIL]",
        )
        self.assertEqual(
            sanitized["metadata"]["network"][0]["host"],
            "[REDACTED_IP]",
        )
        self.assertIn(
            "[REDACTED_SECRET]",
            sanitized["metadata"]["network"][0]["token"],
        )


class TestFailClosedOutboundBoundary(unittest.TestCase):

    def setUp(self):
        self.valid_headers = {
            "X-AI-Vendor": "anthropic",
        }

        self.valid_event = {
            "headers": self.valid_headers,
            "body": json.dumps(
                {
                    "model": "test-model",
                    "messages": [],
                }
            ),
        }

        self.api_key_patch = patch.dict(
            os.environ,
            {
                "ANTHROPIC_API_KEY": (
                    "test-key-abcdefghijklmnopqrstuvwxyz"
                ),
            },
            clear=False,
        )
        self.api_key_patch.start()

    def tearDown(self):
        self.api_key_patch.stop()

    def assert_no_outbound_request(self, event):
        with patch.object(
            index.http,
            "request",
        ) as request_mock:
            response = index.handler(event, None)
            request_mock.assert_not_called()
        return response

    def test_malformed_json_never_calls_network(self):
        event = {
            "headers": self.valid_headers,
            "body": '{"model": ',
        }

        response = self.assert_no_outbound_request(event)

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(
            json.loads(response["body"])["error"],
            "Malformed JSON",
        )

    def test_unknown_vendor_never_calls_network(self):
        event = {
            "headers": {"X-AI-Vendor": "attacker-controlled"},
            "body": json.dumps({"messages": []}),
        }

        response = self.assert_no_outbound_request(event)
        self.assertEqual(response["statusCode"], 400)

    def test_request_controlled_url_is_not_a_vendor(self):
        malicious_urls = (
            "http://127.0.0.1",
            "http://169.254.169.254",
            "http://10.0.0.1",
            "http://172.16.0.1",
            "http://192.168.1.1",
            "https://attacker.example",
        )

        for malicious_url in malicious_urls:
            with self.subTest(malicious_url=malicious_url):
                event = {
                    "headers": {
                        "X-AI-Vendor": malicious_url,
                    },
                    "body": json.dumps({"messages": []}),
                }
                response = self.assert_no_outbound_request(event)
                self.assertEqual(response["statusCode"], 400)

    def test_legacy_vendor_endpoint_header_is_ignored(self):
        event = {
            "headers": {
                "X-AI-Vendor": "anthropic",
                "X-Vendor-Endpoint": (
                    "http://169.254.169.254/"
                    "latest/meta-data/"
                ),
            },
            "body": json.dumps({"messages": []}),
        }

        upstream_response = Mock()
        upstream_response.status = 200
        upstream_response.headers = {
            "Content-Type": "application/json",
        }
        upstream_response.data = b'{"ok":true}'

        with patch.object(
            index.http,
            "request",
            return_value=upstream_response,
        ) as request_mock:
            response = index.handler(event, None)

        self.assertEqual(response["statusCode"], 200)
        request_mock.assert_called_once()
        request_args = request_mock.call_args

        self.assertEqual(request_args.args[0], "POST")
        self.assertEqual(
            request_args.args[1],
            index.VENDOR_ENDPOINTS["anthropic"],
        )
        self.assertNotIn(
            "169.254.169.254",
            request_args.args[1],
        )

    def test_missing_vendor_never_calls_network(self):
        event = {
            "headers": {},
            "body": json.dumps({"messages": []}),
        }

        response = self.assert_no_outbound_request(event)
        self.assertEqual(response["statusCode"], 400)

    def test_missing_credentials_never_calls_network(self):
        with patch.dict(os.environ, {}, clear=True):
            response = self.assert_no_outbound_request(
                self.valid_event
            )

        self.assertEqual(response["statusCode"], 500)
        self.assertEqual(
            json.loads(response["body"])["error"],
            "Internal gateway error",
        )

    def test_sanitization_failure_never_calls_network(self):
        with patch.object(
            index,
            "sanitize_payload",
            side_effect=index.SanitizationError("forced failure"),
        ):
            response = self.assert_no_outbound_request(
                self.valid_event
            )

        self.assertEqual(response["statusCode"], 400)
        self.assertEqual(
            json.loads(response["body"])["error"],
            "Request sanitization failed",
        )

    def test_upstream_request_uses_fixed_endpoint(self):
        upstream_response = Mock()
        upstream_response.status = 200
        upstream_response.headers = {
            "Content-Type": "application/json",
        }
        upstream_response.data = b'{"status":"ok"}'

        with patch.object(
            index.http,
            "request",
            return_value=upstream_response,
        ) as request_mock:
            response = index.handler(self.valid_event, None)

        self.assertEqual(response["statusCode"], 200)
        request_mock.assert_called_once()
        call_args = request_mock.call_args

        self.assertEqual(call_args.args[0], "POST")
        self.assertEqual(
            call_args.args[1],
            "https://api.anthropic.com/v1/messages",
        )
        self.assertFalse(call_args.kwargs["redirect"])
        self.assertFalse(call_args.kwargs["retries"])

    def test_upstream_exception_does_not_leak_details(self):
        with patch.object(
            index.http,
            "request",
            side_effect=index.urllib3.exceptions.HTTPError(
                "internal upstream diagnostic"
            ),
        ):
            response = index.handler(self.valid_event, None)

        body = json.loads(response["body"])

        self.assertEqual(response["statusCode"], 502)
        self.assertEqual(
            body["error"],
            "Upstream AI service unavailable",
        )
        self.assertNotIn(
            "internal upstream diagnostic",
            response["body"],
        )


class TestStaticVendorConfiguration(unittest.TestCase):

    def test_endpoint_requires_https(self):
        with patch.dict(
            index.VENDOR_ENDPOINTS,
            {
                "anthropic": (
                    "http://api.anthropic.com/v1/messages"
                ),
            },
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                index.get_vendor_endpoint("anthropic")

    def test_endpoint_requires_host(self):
        with patch.dict(
            index.VENDOR_ENDPOINTS,
            {"anthropic": "https://"},
            clear=True,
        ):
            with self.assertRaises(RuntimeError):
                index.get_vendor_endpoint("anthropic")

    def test_unknown_vendor_is_rejected(self):
        with self.assertRaises(ValueError):
            index.get_vendor(
                {"X-AI-Vendor": "http://127.0.0.1"}
            )


if __name__ == "__main__":
    print(
        "[INFO] Starting deterministic DLP security validation..."
    )
    unittest.main(verbosity=2)
