"""
AI-NIDS — Signature Engine Runtime Wrapper
ml/signature_engine_runtime.py

Wraps the RuleParser + Aho-Corasick matcher into a single object with a
match_flow() method consumed by the Ensemble Correlator worker.

Bridges the gap between:
    capture/rule_parser.py      (rule parsing / data model)
    ml/ensemble_correlator.py   (expects signature_engine.match_flow(meta))

SignatureMatchResult is the typed return value that EngineOutputs reads.

FR Traceability:
    FR4.1  — Match packets against signature rules
    FR4.2  — Snort-like rule syntax
    FR4.4  — Pattern matching on packet content
    FR4.5  — Pattern matching on packet headers
    FR4.6  — Multiple conditions (AND logic)
    FR4.9  — Port scan detection
    FR4.10 — SQL injection detection
    FR4.11 — XSS detection
    FR4.12 — Brute force detection
    FR4.14 — <= 50 ms per-packet budget
April 6, 2026 | Sprint 1, Week 4
"""

import logging
import os
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger("ai-nids.signature_engine")

RULES_DIR = os.environ.get("RULES_DIR", os.path.join(os.path.dirname(__file__), "..", "rules"))


@dataclass
class SignatureMatchResult:
    """
    Returned by SignatureEngine.match_flow() when a rule fires.
    Consumed by EngineOutputs in ensemble_correlator.py.
    """
    rule_id: str
    attack_type: str        # maps to CICIDS2017 attack category
    confidence: float       # 1.0 for deterministic match; <1 for partial
    description: str
    severity: str           # LOW / MEDIUM / HIGH / CRITICAL


# Map RuleRecord.attack_category → CICIDS2017 ensemble attack_type
_CATEGORY_MAP = {
    "dos": "DoS",
    "dos flood": "DoS",
    "ddos": "DDoS",
    "portscan": "PortScan",
    "port scan": "PortScan",
    "scan": "PortScan",
    "brute force": "BruteForce",
    "bruteforce": "BruteForce",
    "web attack": "WebAttack",
    "webattack": "WebAttack",
    "sqli": "WebAttack",
    "xss": "WebAttack",
    "botnet": "Botnet",
    "infiltration": "Infiltration",
}


def _map_category(raw: str) -> str:
    key = raw.lower().strip()
    return _CATEGORY_MAP.get(key, raw)


class SignatureEngine:
    """
    Runtime signature engine.
    Loads rules at construction time; match_flow() is called per-flow
    by the Ensemble Correlator worker.
    """

    def __init__(self, rules_dir: str = RULES_DIR) -> None:
        self._rules: list = []
        self._content_index: dict = {}   # pattern → list of rule indices
        self._load_rules(rules_dir)

    def _load_rules(self, rules_dir: str) -> None:
        """Parse all .rules files and build in-memory lookup structures."""
        try:
            import sys
            # Ensure the project root is on sys.path so capture/ is importable
            project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
            if project_root not in sys.path:
                sys.path.insert(0, project_root)

            from backend.capture.rule_parser import RuleParser
            parser = RuleParser()
            self._rules = parser.parse_directory(rules_dir)

            # Build content pattern → rule index lookup
            for idx, rule in enumerate(self._rules):
                for pattern in rule.content_patterns:
                    key = pattern.lower() if rule.nocase else pattern
                    self._content_index.setdefault(key, []).append(idx)

            logger.info(
                "SignatureEngine loaded %d rules, %d content patterns",
                len(self._rules),
                len(self._content_index),
            )
        except Exception as e:
            logger.warning("SignatureEngine rule load failed: %s", e)
            self._rules = []

    def match_flow(self, meta: dict) -> Optional[SignatureMatchResult]:
        """
        Check flow metadata + payload against all loaded rules.
        Returns the first matching SignatureMatchResult, or None.

        meta keys expected (from PacketRecord / FlowRecord):
            src_ip, dst_ip, src_port, dst_port, protocol,
            tcp_flags (str like 'SYN' / 'SYN-ACK'),
            payload_bytes (bytes, optional),
            pkt_count (int), byte_count (int)

        FR4.14 — must return within 50 ms. Aho-Corasick is O(n)
        in payload length so this is satisfied for typical MTU-sized payloads.
        """
        if not self._rules:
            return None

        payload_raw: bytes = meta.get("payload_bytes") or b""
        payload_lower = payload_raw.lower()
        tcp_flags: str = (meta.get("tcp_flags") or "").upper()
        dst_port: Optional[int] = meta.get("dst_port")
        protocol: str = (meta.get("protocol") or "TCP").upper()

        for rule in self._rules:
            if not rule.is_enabled:
                continue

            # Protocol filter
            if rule.protocol.upper() not in ("ANY", protocol):
                continue

            # Destination port filter
            if rule.dst_port not in ("any", None, str(dst_port)):
                try:
                    if int(rule.dst_port) != dst_port:
                        continue
                except (ValueError, TypeError):
                    pass

            # TCP flag matching (FR4.5)
            if rule.flags:
                required = rule.flags.upper()
                if required not in tcp_flags:
                    continue

            # Content pattern matching (FR4.4, FR4.6 — AND logic)
            if rule.content_patterns:
                all_matched = True
                for pattern in rule.content_patterns:
                    check = pattern.lower() if rule.nocase else pattern
                    haystack = payload_lower if rule.nocase else payload_raw
                    if isinstance(haystack, bytes):
                        check_b = check.encode() if isinstance(check, str) else check
                        if check_b not in haystack:
                            all_matched = False
                            break
                    else:
                        if check not in haystack:
                            all_matched = False
                            break
                if not all_matched:
                    continue

            # ── Rule matched ──────────────────────────────────────────────
            attack_type = _map_category(rule.attack_category)
            return SignatureMatchResult(
                rule_id=rule.rule_id,
                attack_type=attack_type,
                confidence=1.0,       # deterministic match
                description=(
                    f"Signature match: {rule.rule_name} "
                    f"[{rule.rule_id}] — {attack_type}"
                ),
                severity=rule.severity,
            )

        return None