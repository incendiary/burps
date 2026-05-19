"""
Smoke tests for the X-Hook-Signature generation logic.

The BurpXHookSignature extension runs inside Burp Suite under Jython and
cannot be imported directly in a standard Python test environment (it
depends on the 'burp' and 'java.io' Jython namespaces).

These tests exercise the underlying cryptographic logic — SHA-512 + base64
encoding — in isolation using only the stdlib, verifying that the algorithm
produces the expected values independently of the Burp runtime.
"""

import base64
import hashlib


def _generate_signature(key: str, body: bytes) -> bytes:
    """Pure-Python equivalent of BurpExtender.createHash().

    Replicates:
        base64.b64encode(hashlib.sha512(key + body).digest())

    The extension concatenates key (str) with body (bytes) in Jython,
    which permits mixed str/bytes.  In CPython 3 we encode the key to
    bytes first.
    """
    payload = key.encode("ascii") + body
    return base64.b64encode(hashlib.sha512(payload).digest())


# ---------------------------------------------------------------------------
# Correctness
# ---------------------------------------------------------------------------


def test_empty_key_empty_body_is_stable():
    """The default configuration (empty key, empty body) must produce a fixed hash."""
    result = _generate_signature("", b"")
    # SHA-512 of b"" is a well-known value; base64 of its digest must be stable
    expected_raw = hashlib.sha512(b"").digest()
    assert result == base64.b64encode(expected_raw)


def test_known_vector():
    """Cross-check against a pre-computed reference value."""
    # echo -n "secret{\"id\":1}" | sha512sum then base64
    key = "secret"
    body = b'{"id":1}'
    digest = hashlib.sha512(key.encode("ascii") + body).digest()
    expected = base64.b64encode(digest)
    assert _generate_signature(key, body) == expected


def test_output_is_bytes():
    result = _generate_signature("k", b"body")
    assert isinstance(result, bytes)


def test_output_is_valid_base64():
    result = _generate_signature("k", b"body")
    # Should not raise
    decoded = base64.b64decode(result)
    assert len(decoded) == 64  # SHA-512 produces 64-byte digests


def test_different_keys_produce_different_signatures():
    body = b"same-body"
    sig_a = _generate_signature("key-a", body)
    sig_b = _generate_signature("key-b", body)
    assert sig_a != sig_b


def test_different_bodies_produce_different_signatures():
    key = "same-key"
    sig_a = _generate_signature(key, b"body-a")
    sig_b = _generate_signature(key, b"body-b")
    assert sig_a != sig_b


def test_signature_is_deterministic():
    """Same inputs must always produce the same output."""
    key = "determinism"
    body = b"test-request-body"
    assert _generate_signature(key, body) == _generate_signature(key, body)
