"""Cipher suite string parsing and policy filtering.

OpenSSL style cipher strings and IANA style TLS 1.3 names are both accepted.
A suite can be described structurally, ordered by strength, tested for forward
secrecy, and filtered against an operator policy that constrains versions,
name prefixes and weak constructions.
"""

from __future__ import annotations

from typing import Any, Dict, List, Mapping, Optional, Sequence, Tuple

_CATALOG_ROWS: Tuple[Tuple[str, str, Optional[str], str, Optional[str], str], ...] = (
    ("TLS_AES_128_GCM_SHA256", "TLS13", None, "AES128-GCM", None, "TLS1.3"),
    ("TLS_AES_256_GCM_SHA384", "TLS13", None, "AES256-GCM", None, "TLS1.3"),
    ("TLS_CHACHA20_POLY1305_SHA256", "TLS13", None, "CHACHA20-POLY1305", None, "TLS1.3"),
    ("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE", "ECDSA", "AES128-GCM", None, "TLS1.2"),
    ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE", "ECDSA", "AES256-GCM", None, "TLS1.2"),
    ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", "RSA", "AES128-GCM", None, "TLS1.2"),
    ("ECDHE-RSA-AES256-GCM-SHA384", "ECDHE", "RSA", "AES256-GCM", None, "TLS1.2"),
    ("ECDHE-RSA-AES128-SHA256", "ECDHE", "RSA", "AES128-CBC", "SHA256", "TLS1.2"),
    ("ECDHE-RSA-AES256-SHA384", "ECDHE", "RSA", "AES256-CBC", "SHA384", "TLS1.2"),
    ("ECDHE-RSA-AES128-SHA", "ECDHE", "RSA", "AES128-CBC", "SHA", "TLS1.0"),
    ("ECDHE-RSA-RC4-SHA", "ECDHE", "RSA", "RC4", "SHA", "TLS1.0"),
    ("ECDHE-RSA-DES-CBC3-SHA", "ECDHE", "RSA", "3DES-CBC", "SHA", "TLS1.0"),
    ("AES128-GCM-SHA256", "RSA", "RSA", "AES128-GCM", None, "TLS1.2"),
    ("AES256-GCM-SHA384", "RSA", "RSA", "AES256-GCM", None, "TLS1.2"),
    ("AES128-SHA", "RSA", "RSA", "AES128-CBC", "SHA", "TLS1.1"),
    ("DES-CBC3-SHA", "RSA", "RSA", "3DES-CBC", "SHA", "TLS1.0"),
    ("RC4-SHA", "RSA", "RSA", "RC4", "SHA", "TLS1.0"),
    ("NULL-SHA", "RSA", "RSA", "NULL", "SHA", "TLS1.0"),
    ("EXP-DES-CBC-SHA", "RSA", "RSA", "DES-CBC", "SHA", "TLS1.0"),
)

_FIELDS = ("kx", "auth", "enc", "mac", "version")

_CATALOG: Dict[str, Dict[str, Any]] = {
    row[0]: dict(zip(_FIELDS, row[1:])) for row in _CATALOG_ROWS
}

_ORDER: Tuple[str, ...] = tuple(row[0] for row in _CATALOG_ROWS)

_VERSION_RANK = {"TLS1.3": 3, "TLS1.2": 2, "TLS1.1": 1, "TLS1.0": 0}

_ENC_RANK = {
    "CHACHA20-POLY1305": 90,
    "AES256-GCM": 80,
    "AES128-GCM": 70,
    "AES256-CBC": 60,
    "AES128-CBC": 50,
    "DES-CBC": 30,
    "3DES-CBC": 25,
    "RC4": 20,
    "NULL": 10,
}

_KX_RANK = {"TLS13": 3, "ECDHE": 2, "RSA": 1}

_MAC_RANK: Dict[Optional[str], int] = {"SHA384": 5, "SHA256": 4, "SHA": 3, "MD5": 2, None: 0}


def _expand(token: str) -> List[str]:
    wanted = token.strip().upper()
    if not wanted:
        return []
    if wanted == "ALL":
        return list(_ORDER)
    return [name for name in _ORDER if name.upper().startswith(wanted)]


def parse_list(text: str) -> List[str]:
    """Expand an OpenSSL style cipher string into an ordered suite list."""
    names: List[str] = []
    excluded: List[str] = []
    for raw in text.split(":"):
        token = raw.strip()
        if not token:
            continue
        if token == "@STRENGTH":
            names = sorted(names, reverse=True)
        elif token.startswith("!"):
            pattern = token[1:].strip().upper()
            names = [name for name in names if not name.upper().startswith(pattern)]
        elif token.startswith("+"):
            pattern = token[1:].strip().upper()
            matched = [name for name in names if name.upper().startswith(pattern)]
            if matched:
                names = [name for name in names if name not in matched] + sorted(matched)
        else:
            for name in _expand(token):
                if name not in names:
                    names.append(name)
    return names


def describe(name: str) -> Dict[str, Any]:
    """Return the structural components of a known cipher suite."""
    info = _CATALOG.get(name)
    if info is None:
        raise ValueError("unknown-suite")
    result = dict(info)
    if result["version"] == "TLS1.3":
        result["kx"] = None
    if result["enc"].endswith("-CBC"):
        result["enc"] = result["enc"][:-4]
    if result["mac"] is None:
        _head, separator, tail = name.rpartition("SHA")
        if separator:
            result["mac"] = "SHA" + tail
    return result


def _strength(info: Mapping[str, Any]) -> Tuple[int, int, int, int]:
    return (
        _VERSION_RANK.get(info["version"], 0),
        _ENC_RANK.get(info["enc"], 0),
        _KX_RANK.get(info["kx"], 0),
        _MAC_RANK.get(info["mac"], 0),
    )


def order_by_strength(names: Sequence[str]) -> List[str]:
    """Order suites from strongest to weakest, keeping ties in input order."""
    return sorted(names, key=lambda item: _strength(describe(item)), reverse=True)


def _is_weak(name: str, info: Mapping[str, Any]) -> bool:
    if "EXPORT" in name.upper():
        return True
    return info["enc"] in ("RC4", "3DES", "NULL")


def filter_policy(
    offered: Sequence[str], policy: Optional[Mapping[str, Any]] = None
) -> List[str]:
    """Keep the offered suites that satisfy a policy, preserving input order."""
    rules: Mapping[str, Any] = policy or {}
    minimum = rules.get("min_version")
    allow = [str(item).lower() for item in (rules.get("allow") or [])]
    deny = [str(item) for item in (rules.get("deny") or [])]
    kept: List[str] = []
    for name in offered:
        info = _CATALOG.get(name)
        if info is None:
            continue
        if _is_weak(name, info):
            continue
        if minimum and _VERSION_RANK.get(info["version"], 0) <= _VERSION_RANK.get(str(minimum), 0):
            continue
        lowered = name.lower()
        if allow and not any(lowered.startswith(prefix) for prefix in allow):
            continue
        if deny and any(name.startswith(prefix) for prefix in deny):
            continue
        kept.append(name)
    return kept


def is_forward_secret(name: str) -> bool:
    """Return whether the suite always uses an ephemeral key exchange."""
    return describe(name)["enc"] != "NULL"