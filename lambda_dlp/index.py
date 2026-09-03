import json
import logging
import os
import re
from typing import Any

import urllib3

IP_REGEX = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
EMAIL_REGEX = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
CREDENTIAL_KEY_REGEX = re.compile(
    r'''(?ix)(?<![A-Za-z0-9])(api[_-]?key|secret|password|bearer|token)\s*[:=]\s*["']?[A-Za-z0-9_.~\-]{16,}["']?'''
)

VENDOR_ENDPOINTS = {
    "anthropic": "https://api.anthropic.com/v1/messages",
}

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

http = urllib3.PoolManager(
    retries=False,
    timeout=urllib3.Timeout(connect=3.0, read=10.0),
)


class SanitizationError(Exception):
    """Raised when untrusted input cannot be safely sanitized."""


def sanitize_text(text: str) -> str:
    if not isinstance(text, str):
        raise SanitizationError("Expected string input")
    try:
        text = IP_REGEX.sub("[REDACTED_IP]", text)
        text = EMAIL_REGEX.sub("[REDACTED_EMAIL]", text)
        text = CREDENTIAL_KEY_REGEX.sub(
            r'\1: "[REDACTED_SECRET]"',
            text,
        )
        return text
    except Exception as exc:
        raise SanitizationError("Text sanitization failed") from exc


def sanitize_payload(payload: Any) -> Any:
    try:
        if isinstance(payload, dict):
            return {str(key): sanitize_payload(value) for key, value in payload.items()}
        if isinstance(payload, list):
            return [sanitize_payload(item) for item in payload]
        if isinstance(payload, str):
            return sanitize_text(payload)
        if payload is None or isinstance(payload, (bool, int, float)):
            return payload
        raise SanitizationError(f"Unsupported payload type: {type(payload).__name__}")
    except SanitizationError:
        raise
    except Exception as exc:
        raise SanitizationError("Payload sanitization failed") from exc


def get_vendor(headers: dict[str, Any]) -> str:
    vendor = None
    for key, value in headers.items():
        if key.lower() == "x-ai-vendor":
            vendor = value
            break
    if not isinstance(vendor, str):
        raise ValueError("Missing AI vendor")
    vendor = vendor.strip().lower()
    if vendor not in VENDOR_ENDPOINTS:
        raise ValueError("Unknown AI vendor")
    return vendor


def get_vendor_endpoint(vendor: str) -> str:
    endpoint = VENDOR_ENDPOINTS.get(vendor)
    if not isinstance(endpoint, str):
        raise RuntimeError("Vendor endpoint configuration is invalid")
    parsed = urllib3.util.parse_url(endpoint)
    if parsed.scheme != "https":
        raise RuntimeError("Vendor endpoint must use HTTPS")
    if not parsed.host:
        raise RuntimeError("Vendor endpoint host is missing")
    return endpoint


def get_vendor_api_key(vendor: str) -> str:
    environment_key = {"anthropic": "ANTHROPIC_API_KEY"}.get(vendor)
    if environment_key is None:
        raise RuntimeError("Vendor credential configuration is invalid")
    api_key = os.environ.get(environment_key)
    if not isinstance(api_key, str) or not api_key.strip():
        raise RuntimeError("Vendor credentials are unavailable")
    return api_key


def error_response(status_code: int, error: str) -> dict[str, Any]:
    return {
        "statusCode": status_code,
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps({"error": error}),
    }


def handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    try:
        if not isinstance(event, dict):
            return error_response(400, "Invalid request")

        headers = event.get("headers", {})
        if not isinstance(headers, dict):
            return error_response(400, "Invalid request headers")

        raw_body = event.get("body", "{}")
        if not isinstance(raw_body, str):
            return error_response(400, "Invalid request body")

        try:
            body = json.loads(raw_body)
        except (json.JSONDecodeError, TypeError):
            return error_response(400, "Malformed JSON")

        sanitized_body = sanitize_payload(body)
        vendor = get_vendor(headers)
        vendor_endpoint = get_vendor_endpoint(vendor)
        api_key = get_vendor_api_key(vendor)

        outbound_headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        }

        response = http.request(
            "POST",
            vendor_endpoint,
            body=json.dumps(sanitized_body, separators=(",", ":")),
            headers=outbound_headers,
            redirect=False,
            retries=False,
        )

        return {
            "statusCode": response.status,
            "headers": {
                "Content-Type": response.headers.get(
                    "Content-Type",
                    "application/json",
                )
            },
            "body": response.data.decode("utf-8", errors="replace"),
        }

    except SanitizationError:
        logger.warning("DLP sanitization failure")
        return error_response(400, "Request sanitization failed")

    except ValueError:
        return error_response(400, "Unknown or invalid AI vendor")

    except urllib3.exceptions.HTTPError:
        logger.exception("Upstream AI vendor request failed")
        return error_response(502, "Upstream AI service unavailable")

    except Exception:
        logger.exception("Enterprise AI gateway failure")
        return error_response(500, "Internal gateway error")
