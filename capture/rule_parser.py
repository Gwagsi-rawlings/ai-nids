"""
AI-NIDS — Signature Detection Engine: Rule Parser
capture/rule_parser.py

Parses Snort-compatible rule files into structured SignatureRule objects.
Implements FR4.1 (signature-based detection), FR4.2 (Snort-like syntax),
FR4.3 (parse rules from text files), FR4.4 (pattern matching on content),
FR4.5 (pattern matching on headers), FR4.6 (AND/OR logic),
FR4.13 (enable/disable rules).

March 22, 2026 | Sprint 1 | Developer: GWAGSI Rawlings Nshom
"""

import re
import logging
from dataclasses import dataclass, field
from typing import Optional
from pathlib import Path

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class SignatureRule:
    """
    Represents a single parsed Snort-compatible detection rule.

    Attribute names map directly to Snort rule fields so rules can be
    loaded from existing community rule sets without transformation.
    """
    # Header fields (FR4.5)
    action: str                          # alert | log | pass
    protocol: str                        # tcp | udp | icmp | any
    src_ip: str                          # IP, CIDR, or 'any'
    src_port: str                        # port, range, or 'any'
    direction: str                       # -> or <>
    dst_ip: str                          # IP, CIDR, or 'any'
    dst_port: str                        # port, range, or 'any'

    # Metadata options
    sid: str                             # unique rule ID  (required)
    msg: str                             # human-readable description
    rev: int = 1                         # revision number

    # Detection options (FR4.4 content matching)
    content: list = field(default_factory=list)    # byte patterns to match
    pcre: list = field(default_factory=list)       # Perl regex patterns
    flags: Optional[str] = None          # TCP flags (e.g. 'S', 'SA')
    threshold_type: Optional[str] = None # both | limit | threshold
    threshold_track: Optional[str] = None# by_src | by_dst
    threshold_count: Optional[int] = None
    threshold_seconds: Optional[int] = None
    nocase: bool = False                 # case-insensitive content match

    # Severity / classification
    classtype: Optional[str] = None      # e.g. attempted-dos
    priority: int = 3                    # 1 (Critical) to 4 (Low)

    # Lifecycle (FR4.13)
    enabled: bool = True


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

CLASSTYPE_SEVERITY = {
    "attempted-admin":           "Critical",
    "successful-admin":          "Critical",
    "attempted-dos":             "High",
    "successful-dos":            "High",
    "denial-of-service":         "High",
    "network-scan":              "Medium",
    "attempted-recon":           "Medium",
    "web-application-attack":    "High",
    "sql-injection":             "High",
    "trojan-activity":           "Critical",
    "policy-violation":          "Low",
    "protocol-command-decode":   "Low",
}

PRIORITY_SEVERITY = {
    1: "Critical",
    2: "High",
    3: "Medium",
    4: "Low",
}


def rule_severity(rule: SignatureRule) -> str:
    """Return AI-NIDS severity string for a rule."""
    if rule.classtype and rule.classtype in CLASSTYPE_SEVERITY:
        return CLASSTYPE_SEVERITY[rule.classtype]
    return PRIORITY_SEVERITY.get(rule.priority, "Medium")


# ---------------------------------------------------------------------------
# Parser helpers
# ---------------------------------------------------------------------------

_HEADER_RE = re.compile(
    r"^\s*(?P<action>\w+)"
    r"\s+(?P<proto>\w+)"
    r"\s+(?P<src_ip>[^\s]+)"
    r"\s+(?P<src_port>[^\s]+)"
    r"\s+(?P<direction><>|->)"
    r"\s+(?P<dst_ip>[^\s]+)"
    r"\s+(?P<dst_port>[^\s]+)"
    r"\s*\("
)

_OPT_SPLIT_RE = re.compile(r';(?=(?:[^"]*"[^"]*")*[^"]*$)')
_OPT_KV_RE    = re.compile(r'^(?P<key>\w+)(?:\s*:\s*(?P<value>.+))?$')


def _parse_options(options_body: str) -> dict:
    """Parse the options body of a Snort rule into a key->value dict."""
    body = options_body.rstrip(") \t\n")
    opts = {}
    for token in _OPT_SPLIT_RE.split(body):
        token = token.strip()
        if not token:
            continue
        m = _OPT_KV_RE.match(token)
        if not m:
            continue
        key   = m.group("key").lower()
        value = (m.group("value") or "").strip().strip('"')

        if key in opts:
            existing = opts[key]
            if isinstance(existing, list):
                existing.append(value)
            else:
                opts[key] = [existing, value]
        else:
            opts[key] = value
    return opts


def _parse_threshold(raw: str) -> dict:
    """Parse: type both, track by_src, count 20, seconds 60"""
    result = {}
    for part in raw.split(","):
        kv = part.strip().split(None, 1)
        if len(kv) == 2:
            result[kv[0].strip()] = kv[1].strip()
    return result


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_rule(line: str) -> Optional[SignatureRule]:
    """
    Parse a single rule string into a SignatureRule.
    Returns None for blank lines, comments, or malformed rules.
    Logs warnings instead of raising (FR4.3 robustness).
    """
    line = line.strip()
    if not line or line.startswith("#"):
        return None

    hm = _HEADER_RE.match(line)
    if not hm:
        logger.warning("Skipping unrecognised rule: %.80s", line)
        return None

    paren_pos    = line.index("(") + 1
    options_body = line[paren_pos:]
    opts         = _parse_options(options_body)

    sid = opts.get("sid")
    if not sid:
        logger.warning("Skipping rule without sid: %.80s", line)
        return None

    raw_content = opts.get("content", [])
    if isinstance(raw_content, str):
        raw_content = [raw_content]

    raw_pcre = opts.get("pcre", [])
    if isinstance(raw_pcre, str):
        raw_pcre = [raw_pcre]

    threshold_opts = {}
    if "threshold" in opts:
        threshold_opts = _parse_threshold(opts["threshold"])

    try:
        priority = int(opts.get("priority", 3))
    except ValueError:
        priority = 3

    try:
        rev = int(opts.get("rev", 1))
    except ValueError:
        rev = 1

    return SignatureRule(
        action    = hm.group("action"),
        protocol  = hm.group("proto"),
        src_ip    = hm.group("src_ip"),
        src_port  = hm.group("src_port"),
        direction = hm.group("direction"),
        dst_ip    = hm.group("dst_ip"),
        dst_port  = hm.group("dst_port"),
        sid       = sid,
        msg       = opts.get("msg", ""),
        rev       = rev,
        content   = raw_content,
        pcre      = raw_pcre,
        flags     = opts.get("flags"),
        threshold_type    = threshold_opts.get("type"),
        threshold_track   = threshold_opts.get("track"),
        threshold_count   = int(threshold_opts["count"])   if "count"   in threshold_opts else None,
        threshold_seconds = int(threshold_opts["seconds"]) if "seconds" in threshold_opts else None,
        nocase    = "nocase" in opts,
        classtype = opts.get("classtype"),
        priority  = priority,
        enabled   = True,
    )


def load_rules(path) -> list:
    """
    Load all valid rules from a .rules file.
    Returns empty list (not exception) if file not found. (FR4.3)
    """
    path = Path(path)
    if not path.exists():
        logger.warning("Rule file not found: %s — starting with 0 rules", path)
        return []

    rules = []
    for lineno, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        rule = parse_rule(raw)
        if rule:
            rules.append(rule)
            logger.debug("Loaded rule SID %s (line %d): %s", rule.sid, lineno, rule.msg)

    logger.info("Loaded %d rules from %s", len(rules), path)
    return rules


def load_rules_directory(directory) -> list:
    """Load all *.rules files from a directory, sorted by filename."""
    directory  = Path(directory)
    all_rules  = []
    for rules_file in sorted(directory.glob("*.rules")):
        all_rules.extend(load_rules(rules_file))
    logger.info("Loaded %d total rules from directory: %s", len(all_rules), directory)
    return all_rules


# ---------------------------------------------------------------------------
# Smoke test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    SAMPLE_RULES = [
        "# This is a comment",
        'alert tcp any any -> any 80 (msg:"SQL Injection Attempt"; content:"UNION"; '
        'content:"SELECT"; nocase; classtype:web-application-attack; sid:1001; rev:1;)',
        'alert tcp any any -> any any (msg:"Port Scan Detected"; flags:S; '
        'threshold: type both, track by_src, count 20, seconds 60; '
        'classtype:network-scan; sid:1002; rev:1;)',
        'alert icmp any any -> any any (msg:"Ping Flood"; '
        'threshold: type both, track by_src, count 100, seconds 1; '
        'classtype:attempted-dos; priority:1; sid:1003; rev:2;)',
        'alert tcp any any -> any 80 (msg:"XSS Attempt"; content:"<script>"; '
        'nocase; classtype:web-application-attack; sid:1004; rev:1;)',
        'alert tcp any any -> any 22 (msg:"SSH Brute Force"; '
        'threshold: type both, track by_src, count 5, seconds 60; '
        'classtype:attempted-admin; priority:2; sid:1005; rev:1;)',
        "this is not a valid rule",
        'alert tcp any any -> any 80 (msg:"No SID rule"; content:"test";)',
    ]

    print("\n" + "="*60)
    print("AI-NIDS Rule Parser — Smoke Test")
    print("="*60)

    passed = 0
    failed = 0

    for raw in SAMPLE_RULES:
        rule = parse_rule(raw)
        skip_expected = (raw.startswith("#") or "not a valid" in raw or "No SID" in raw)

        if skip_expected:
            ok = rule is None
            print(f"\n[{'PASS' if ok else 'FAIL'}] SKIP expected: {raw[:60]}")
            if ok: passed += 1
            else:  failed += 1
        else:
            if rule:
                sev = rule_severity(rule)
                print(f"\n[PASS] SID {rule.sid} | {rule.msg}")
                print(f"       {rule.protocol} {rule.src_ip}:{rule.src_port} "
                      f"{rule.direction} {rule.dst_ip}:{rule.dst_port}")
                print(f"       Content: {rule.content} | Flags: {rule.flags} | Nocase: {rule.nocase}")
                if rule.threshold_type:
                    print(f"       Threshold: {rule.threshold_type}/{rule.threshold_track} "
                          f"count={rule.threshold_count} secs={rule.threshold_seconds}")
                print(f"       Severity: {sev} | Enabled: {rule.enabled}")
                passed += 1
            else:
                print(f"\n[FAIL] Expected rule, got None: {raw[:60]}")
                failed += 1

    print("\n" + "="*60)
    print(f"Results: {passed} passed, {failed} failed")
    print("="*60)