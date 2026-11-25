"""Public smoke tests for cipher suite parsing and policy filtering."""

from __future__ import annotations

from ciphersuite import (
    describe,
    filter_policy,
    is_forward_secret,
    parse_list,
)


def test_tls13_suite_description() -> None:
    assert describe("TLS_AES_128_GCM_SHA256") == {
        "kx": "TLS13",
        "auth": None,
        "enc": "AES128-GCM",
        "mac": None,
        "version": "TLS1.3",
    }


def test_cbc_suite_keeps_mode_and_mac() -> None:
    assert describe("AES128-SHA") == {
        "kx": "RSA",
        "auth": "RSA",
        "enc": "AES128-CBC",
        "mac": "SHA",
        "version": "TLS1.1",
    }


def test_forward_secrecy_follows_key_exchange() -> None:
    assert is_forward_secret("ECDHE-RSA-AES128-GCM-SHA256") is True
    assert is_forward_secret("AES128-GCM-SHA256") is False


def test_min_version_keeps_boundary_suite() -> None:
    offered = ["TLS_AES_128_GCM_SHA256", "ECDHE-RSA-AES128-GCM-SHA256"]
    assert filter_policy(offered, {"min_version": "TLS1.2"}) == offered


def test_strength_order_puts_aead_before_rc4() -> None:
    assert parse_list("RC4-SHA:AES256-GCM-SHA384:@STRENGTH") == [
        "AES256-GCM-SHA384",
        "RC4-SHA",
    ]