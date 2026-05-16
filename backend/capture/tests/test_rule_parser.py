"""
AI-NIDS — Unit Tests: Rule Parser
tests/test_rule_parser.py

Covers both public APIs in capture/rule_parser.py:
  1. parse_rule() / SignatureRule  (functional API)
  2. RuleParser / RuleRecord       (class-based API used by signature engine)

FR Traceability:
    FR4.2  — Snort-like rule syntax support
    FR4.3  — Parse detection rules from text files
    FR4.4  — Pattern matching on packet content
    FR4.5  — Pattern matching on packet headers
    FR4.6  — Multiple conditions in a single rule (AND logic)
    FR4.13 — Enable/disable rules

March 24, 2026 | Sprint 1 | Developer: GWAGSI Rawlings Nshom
"""

import tempfile
import textwrap
from pathlib import Path

import pytest

from capture.rule_parser import (
    # Functional API
    parse_rule,
    load_rules,
    load_rules_directory,
    rule_severity,
    SignatureRule,
    CLASSTYPE_SEVERITY,
    PRIORITY_SEVERITY,
    # Class-based API
    RuleParser,
    RuleRecord,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SQLI_RULE = (
    'alert tcp any any -> any 80 '
    '(msg:"SQL Injection UNION SELECT"; '
    'content:"UNION"; content:"SELECT"; nocase; '
    'classtype:web-application-attack; sid:1001; rev:1;)'
)

PORT_SCAN_RULE = (
    'alert tcp any any -> any any '
    '(msg:"Port Scan SYN Sweep"; '
    'flags:S; '
    'threshold: type both, track by_src, count 20, seconds 60; '
    'classtype:network-scan; sid:1002; rev:1;)'
)

ICMP_FLOOD_RULE = (
    'alert icmp any any -> any any '
    '(msg:"Ping Flood DoS"; '
    'threshold: type both, track by_src, count 100, seconds 1; '
    'classtype:attempted-dos; priority:1; sid:1003; rev:2;)'
)

XSS_RULE = (
    'alert tcp any any -> any 80 '
    '(msg:"XSS Script Tag Attempt"; '
    'content:"<script"; nocase; '
    'classtype:web-application-attack; sid:1004; rev:1;)'
)

SSH_BRUTE_RULE = (
    'alert tcp any any -> any 22 '
    '(msg:"SSH Brute Force Attempt"; '
    'flags:S; '
    'threshold: type both, track by_src, count 5, seconds 60; '
    'classtype:attempted-admin; priority:2; sid:1005; rev:1;)'
)

ALL_VALID_RULES = [SQLI_RULE, PORT_SCAN_RULE, ICMP_FLOOD_RULE, XSS_RULE, SSH_BRUTE_RULE]


@pytest.fixture
def rules_file(tmp_path):
    """Write a temporary .rules file with 5 valid rules + 2 invalid lines."""
    content = "\n".join([
        "# This is a comment — must be skipped",
        SQLI_RULE,
        PORT_SCAN_RULE,
        ICMP_FLOOD_RULE,
        XSS_RULE,
        SSH_BRUTE_RULE,
        "this is not a valid rule",
        'alert tcp any any -> any 80 (msg:"No SID"; content:"test";)',
    ])
    f = tmp_path / "test.rules"
    f.write_text(content, encoding="utf-8")
    return f


@pytest.fixture
def rules_directory(tmp_path):
    """Write two separate .rules files into a temp directory."""
    (tmp_path / "sqli.rules").write_text(SQLI_RULE + "\n" + XSS_RULE, encoding="utf-8")
    (tmp_path / "scan.rules").write_text(PORT_SCAN_RULE, encoding="utf-8")
    return tmp_path


# ===========================================================================
# Section 1 — parse_rule() / SignatureRule functional API
# ===========================================================================

class TestParseRule:
    """Tests for the parse_rule() function."""

    def test_sqli_rule_parsed_correctly(self):
        rule = parse_rule(SQLI_RULE)
        assert rule is not None
        assert rule.sid == "1001"
        assert rule.action == "alert"
        assert rule.protocol == "tcp"
        assert rule.dst_port == "80"

    def test_sqli_rule_content_patterns(self):
        rule = parse_rule(SQLI_RULE)
        assert "UNION" in rule.content
        assert "SELECT" in rule.content

    def test_sqli_rule_nocase_flag(self):
        rule = parse_rule(SQLI_RULE)
        assert rule.nocase is True

    def test_port_scan_rule_flags(self):
        rule = parse_rule(PORT_SCAN_RULE)
        assert rule is not None
        assert rule.flags == "S"

    def test_port_scan_threshold_parsed(self):
        rule = parse_rule(PORT_SCAN_RULE)
        assert rule.threshold_type == "both"
        assert rule.threshold_track == "by_src"
        assert rule.threshold_count == 20
        assert rule.threshold_seconds == 60

    def test_icmp_rule_protocol(self):
        rule = parse_rule(ICMP_FLOOD_RULE)
        assert rule is not None
        assert rule.protocol == "icmp"

    def test_icmp_rule_priority(self):
        rule = parse_rule(ICMP_FLOOD_RULE)
        assert rule.priority == 1

    def test_icmp_rule_revision(self):
        rule = parse_rule(ICMP_FLOOD_RULE)
        assert rule.rev == 2

    def test_rule_enabled_by_default(self):
        rule = parse_rule(SQLI_RULE)
        assert rule.enabled is True

    def test_comment_line_returns_none(self):
        assert parse_rule("# This is a comment") is None

    def test_blank_line_returns_none(self):
        assert parse_rule("") is None
        assert parse_rule("   ") is None

    def test_malformed_rule_returns_none(self):
        assert parse_rule("this is not a rule at all") is None

    def test_rule_without_sid_returns_none(self):
        no_sid = 'alert tcp any any -> any 80 (msg:"No SID"; content:"test";)'
        assert parse_rule(no_sid) is None

    def test_bidirectional_direction_operator(self):
        bidir = (
            'alert tcp any any <> any 80 '
            '(msg:"Bidirectional Rule"; sid:9001; rev:1;)'
        )
        rule = parse_rule(bidir)
        assert rule is not None
        assert rule.direction == "<>"

    def test_classtype_extracted(self):
        rule = parse_rule(SQLI_RULE)
        assert rule.classtype == "web-application-attack"

    def test_msg_extracted(self):
        rule = parse_rule(SQLI_RULE)
        assert "SQL Injection" in rule.msg

    def test_returns_signature_rule_instance(self):
        rule = parse_rule(SQLI_RULE)
        assert isinstance(rule, SignatureRule)


class TestLoadRules:
    """Tests for load_rules() — reads a .rules file."""

    def test_loads_correct_count(self, rules_file):
        rules = load_rules(rules_file)
        assert len(rules) == 5

    def test_all_rules_are_signature_rule_instances(self, rules_file):
        rules = load_rules(rules_file)
        assert all(isinstance(r, SignatureRule) for r in rules)

    def test_nonexistent_file_returns_empty_list(self, tmp_path):
        rules = load_rules(tmp_path / "does_not_exist.rules")
        assert rules == []

    def test_comments_excluded(self, rules_file):
        rules = load_rules(rules_file)
        sids = [r.sid for r in rules]
        assert all(s in ["1001", "1002", "1003", "1004", "1005"] for s in sids)

    def test_all_rules_enabled(self, rules_file):
        rules = load_rules(rules_file)
        assert all(r.enabled for r in rules)


class TestLoadRulesDirectory:
    """Tests for load_rules_directory()."""

    def test_loads_from_multiple_files(self, rules_directory):
        rules = load_rules_directory(rules_directory)
        # sqli.rules has 2, scan.rules has 1
        assert len(rules) == 3

    def test_empty_directory_returns_empty_list(self, tmp_path):
        rules = load_rules_directory(tmp_path)
        assert rules == []


class TestRuleSeverity:
    """Tests for rule_severity() helper."""

    def test_attempted_dos_maps_to_high(self):
        rule = parse_rule(ICMP_FLOOD_RULE)
        assert rule_severity(rule) == "High"

    def test_network_scan_maps_to_medium(self):
        rule = parse_rule(PORT_SCAN_RULE)
        assert rule_severity(rule) == "Medium"

    def test_web_application_attack_maps_to_high(self):
        rule = parse_rule(SQLI_RULE)
        assert rule_severity(rule) == "High"

    def test_attempted_admin_maps_to_critical(self):
        rule = parse_rule(SSH_BRUTE_RULE)
        assert rule_severity(rule) == "Critical"

    def test_unknown_classtype_falls_back_to_priority(self):
        """Rule with unknown classtype but priority=2 should map to High."""
        rule_str = (
            'alert tcp any any -> any 80 '
            '(msg:"Unknown classtype"; classtype:unknown-type; priority:2; sid:9999; rev:1;)'
        )
        rule = parse_rule(rule_str)
        assert rule is not None
        # classtype unknown → falls back to PRIORITY_SEVERITY[2] = "High"
        assert rule_severity(rule) == "High"


# ===========================================================================
# Section 2 — RuleParser / RuleRecord class-based API
# ===========================================================================

@pytest.fixture
def parser():
    return RuleParser()


@pytest.fixture
def mixed_rules_file(tmp_path):
    """Rules file for RuleParser — includes valid + invalid lines."""
    content = textwrap.dedent("""\
        # Comment — skip
        alert icmp any any -> any any (msg:"DoS ICMP Flood"; threshold: type both, track by_src, count 100, seconds 1; sid:1001; rev:1;)
        alert tcp any any -> any any (msg:"Port Scan SYN Sweep"; flags:S; threshold: type both, track by_src, count 20, seconds 60; sid:1002; rev:1;)
        alert tcp any any -> any 22 (msg:"Brute Force SSH Login Attempt"; flags:S; threshold: type both, track by_src, count 10, seconds 30; sid:1003; rev:1;)
        alert tcp any any -> any 80 (msg:"SQL Injection UNION SELECT"; content:"UNION"; content:"SELECT"; nocase; sid:1004; rev:1;)
        alert tcp any any -> any 80 (msg:"XSS Script Tag Attempt"; content:"<script"; nocase; sid:1005; rev:1;)
        not a valid rule at all
        alert tcp any any -> any 80 (msg:"No SID Rule"; content:"test";)
    """)
    f = tmp_path / "mixed.rules"
    f.write_text(content, encoding="utf-8")
    return f


class TestRuleParserParseFile:
    """Tests for RuleParser.parse_file()."""

    def test_returns_five_valid_records(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        assert len(records) == 5

    def test_all_records_are_rule_record_instances(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        assert all(isinstance(r, RuleRecord) for r in records)

    def test_nonexistent_file_returns_empty(self, parser, tmp_path):
        records = parser.parse_file(tmp_path / "nope.rules", category="Test")
        assert records == []

    def test_category_propagated_to_records(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="DoS")
        assert all(r.attack_category == "DoS" for r in records)

    def test_sid_1004_content_patterns(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        sqli = next(r for r in records if r.rule_id == "1004")
        assert "UNION" in sqli.content_patterns
        assert "SELECT" in sqli.content_patterns

    def test_sid_1004_nocase(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        sqli = next(r for r in records if r.rule_id == "1004")
        assert sqli.nocase is True

    def test_sid_1002_flags(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        scan = next(r for r in records if r.rule_id == "1002")
        assert scan.flags == "S"

    def test_sid_1001_threshold(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        flood = next(r for r in records if r.rule_id == "1001")
        assert flood.threshold_count == 100
        assert flood.threshold_seconds == 1

    def test_sid_1005_content_pattern(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        xss = next(r for r in records if r.rule_id == "1005")
        assert "<script" in xss.content_patterns

    def test_raw_field_preserved(self, parser, mixed_rules_file):
        """Each RuleRecord must retain the original rule text for audit."""
        records = parser.parse_file(mixed_rules_file, category="Test")
        for r in records:
            assert len(r.raw) > 0

    def test_enabled_true_by_default(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        assert all(r.enabled for r in records)


class TestRuleParserParseDirectory:
    """Tests for RuleParser.parse_directory()."""

    def test_loads_from_all_rule_files(self, parser, tmp_path):
        (tmp_path / "sqli.rules").write_text(SQLI_RULE + "\n" + XSS_RULE, encoding="utf-8")
        (tmp_path / "scan.rules").write_text(PORT_SCAN_RULE, encoding="utf-8")
        records = parser.parse_directory(tmp_path)
        assert len(records) == 3

    def test_category_derived_from_filename(self, parser, tmp_path):
        (tmp_path / "dos_flood.rules").write_text(ICMP_FLOOD_RULE, encoding="utf-8")
        records = parser.parse_directory(tmp_path)
        # stem "dos_flood" → title-cased "Dos Flood"
        assert records[0].attack_category == "Dos Flood"

    def test_empty_directory_returns_empty_list(self, parser, tmp_path):
        records = parser.parse_directory(tmp_path)
        assert records == []

    def test_non_rules_files_ignored(self, parser, tmp_path):
        (tmp_path / "readme.txt").write_text("not a rules file", encoding="utf-8")
        (tmp_path / "sqli.rules").write_text(SQLI_RULE, encoding="utf-8")
        records = parser.parse_directory(tmp_path)
        assert len(records) == 1


class TestRuleRecordDataModel:
    """Structural tests for RuleRecord dataclass."""

    def test_rule_record_fields_present(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        r = records[0]
        required = [
            "rule_id", "name", "action", "protocol",
            "src_ip", "src_port", "direction", "dst_ip", "dst_port",
            "attack_category", "severity", "content_patterns",
            "nocase", "enabled", "raw",
        ]
        for field_name in required:
            assert hasattr(r, field_name), f"RuleRecord missing field: {field_name}"

    def test_severity_is_valid_level(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        valid_levels = {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
        for r in records:
            assert r.severity in valid_levels, f"Invalid severity: {r.severity}"

    def test_content_patterns_is_list(self, parser, mixed_rules_file):
        records = parser.parse_file(mixed_rules_file, category="Test")
        for r in records:
            assert isinstance(r.content_patterns, list)