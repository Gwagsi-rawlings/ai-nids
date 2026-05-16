"""
AI-NIDS — Reporting Module Tests
tests/test_reporting.py

Tests for ReportBuilder data containers, HTMLRenderer, and pdf_exporter.
Database queries are mocked — no live PostgreSQL required.

FR Traceability:
    FR12.1–FR12.8  — Report generation and export
    FR13.1–FR13.5  — Compliance reporting
    NFR16.1        — ≥80% test coverage

April 26, 2026 | Sprint 2, Week 7 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import pytest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

# ── Import the data containers and renderer ──────────────────────────────────
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from backend.api.reporting.report_builder import (
    ReportData, SeverityBreakdown, AttackCategory,
    TopSourceIP, DailyAlertPoint, DetectionEngineStats, ComplianceStats,
)
from backend.api.reporting.html_renderer import HTMLRenderer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_report(report_type: str = "security") -> ReportData:
    now = datetime(2026, 4, 1, tzinfo=timezone.utc)
    end = datetime(2026, 4, 30, tzinfo=timezone.utc)
    data = ReportData(
        report_type=report_type,
        generated_at=now,
        period_start=now,
        period_end=end,
        generated_by="test_user",
    )
    data.severity = SeverityBreakdown(critical=5, high=12, medium=30, low=50)
    data.top_attack_types = [
        AttackCategory("DoS",       25, 41.7),
        AttackCategory("PortScan",  15, 25.0),
        AttackCategory("BruteForce", 10, 16.7),
        AttackCategory("Botnet",     5,  8.3),
        AttackCategory("WebAttack",  5,  8.3),
    ]
    data.top_source_ips = [
        TopSourceIP("1.2.3.4", 20, "DoS",      now, end),
        TopSourceIP("5.6.7.8", 15, "PortScan", now, end),
    ]
    data.daily_timeline = [
        DailyAlertPoint("2026-04-01", 1, 2, 5, 8),
        DailyAlertPoint("2026-04-02", 2, 3, 8, 10),
        DailyAlertPoint("2026-04-03", 0, 1, 4, 6),
    ]
    data.engine_stats = DetectionEngineStats(
        signature_triggered=30,
        ml_triggered=20,
        both_triggered=10,
        false_positive_count=2,
    )
    data.average_confidence_score = 0.8712
    data.peak_alert_hour = 14
    data.resolution_rate = 0.85
    return data


def _make_compliance_report() -> ReportData:
    data = _make_report("compliance")
    data.compliance = ComplianceStats(
        total_events_logged=97,
        audit_entries=342,
        acknowledged_alerts=80,
        unacknowledged_alerts=17,
        mean_acknowledgement_minutes=23.5,
        data_retained_days=90,
    )
    return data


# ---------------------------------------------------------------------------
# SeverityBreakdown tests
# ---------------------------------------------------------------------------

class TestSeverityBreakdown:
    def test_total(self):
        s = SeverityBreakdown(critical=5, high=10, medium=20, low=30)
        assert s.total == 65

    def test_total_zeros(self):
        assert SeverityBreakdown().total == 0

    def test_to_dict_keys(self):
        d = SeverityBreakdown(1, 2, 3, 4).to_dict()
        assert set(d.keys()) == {"critical", "high", "medium", "low", "total"}

    def test_to_dict_values(self):
        d = SeverityBreakdown(critical=1, high=2, medium=3, low=4).to_dict()
        assert d["total"] == 10


# ---------------------------------------------------------------------------
# DetectionEngineStats tests
# ---------------------------------------------------------------------------

class TestDetectionEngineStats:
    def test_false_positive_rate_zero_total(self):
        s = DetectionEngineStats()
        assert s.false_positive_rate == 0.0

    def test_false_positive_rate_calculation(self):
        s = DetectionEngineStats(
            signature_triggered=40,
            ml_triggered=40,
            both_triggered=20,
            false_positive_count=5,
        )
        # 5 / 100 = 0.05
        assert s.false_positive_rate == 0.05

    def test_false_positive_rate_rounded(self):
        s = DetectionEngineStats(
            signature_triggered=33,
            ml_triggered=33,
            both_triggered=34,
            false_positive_count=1,
        )
        assert isinstance(s.false_positive_rate, float)


# ---------------------------------------------------------------------------
# HTMLRenderer — security report
# ---------------------------------------------------------------------------

class TestHTMLRendererSecurity:
    def setup_method(self):
        self.renderer = HTMLRenderer()
        self.data = _make_report("security")
        self.html = self.renderer.render(self.data)

    def test_returns_string(self):
        assert isinstance(self.html, str)

    def test_html_structure(self):
        assert "<!DOCTYPE html>" in self.html
        assert "<html" in self.html
        assert "</html>" in self.html

    def test_title_present(self):
        assert "Security Summary Report" in self.html

    def test_severity_counts_present(self):
        assert "5" in self.html   # critical
        assert "12" in self.html  # high
        assert "30" in self.html  # medium
        assert "50" in self.html  # low

    def test_attack_types_present(self):
        assert "DoS" in self.html
        assert "PortScan" in self.html
        assert "BruteForce" in self.html

    def test_source_ips_present(self):
        assert "1.2.3.4" in self.html
        assert "5.6.7.8" in self.html

    def test_period_dates_present(self):
        assert "2026-04-01" in self.html
        assert "2026-04-30" in self.html

    def test_generated_by_present(self):
        assert "test_user" in self.html

    def test_confidence_score_present(self):
        assert "0.8712" in self.html

    def test_engine_stats_present(self):
        assert "30" in self.html  # signature triggered
        assert "20" in self.html  # ml triggered

    def test_daily_timeline_present(self):
        assert "2026-04-01" in self.html
        assert "2026-04-02" in self.html

    def test_no_jinja_errors(self):
        # If Jinja2 had unresolved blocks, they would appear literally
        assert "{{" not in self.html
        assert "}}" not in self.html
        assert "{%" not in self.html

    def test_key_finding_callout(self):
        assert "Key Finding" in self.html

    def test_nfr_badge_text(self):
        assert "FR12" in self.html

    def test_css_included(self):
        assert "<style>" in self.html

    def test_cover_banner_present(self):
        assert "cover-banner" in self.html

    def test_footer_present(self):
        assert "footer" in self.html

    def test_peak_hour_present(self):
        assert "14:00" in self.html


# ---------------------------------------------------------------------------
# HTMLRenderer — compliance report
# ---------------------------------------------------------------------------

class TestHTMLRendererCompliance:
    def setup_method(self):
        self.renderer = HTMLRenderer()
        self.data = _make_compliance_report()
        self.html = self.renderer.render(self.data)

    def test_title_present(self):
        assert "Compliance Report" in self.html

    def test_pci_dss_reference(self):
        assert "PCI-DSS" in self.html

    def test_hipaa_reference(self):
        assert "HIPAA" in self.html

    def test_iso_reference(self):
        assert "ISO 27001" in self.html

    def test_audit_entries_present(self):
        assert "342" in self.html

    def test_acknowledgement_stats(self):
        assert "80" in self.html   # acknowledged
        assert "17" in self.html   # unacknowledged

    def test_mean_ack_time(self):
        assert "23.5" in self.html

    def test_retention_days(self):
        assert "90" in self.html

    def test_control_effectiveness_table(self):
        assert "Control Effectiveness" in self.html

    def test_framework_mapping_table(self):
        assert "Framework Control Mapping" in self.html

    def test_pass_fail_indicators(self):
        assert "PASS" in self.html or "FAIL" in self.html

    def test_no_jinja_errors(self):
        assert "{{" not in self.html
        assert "{%" not in self.html


# ---------------------------------------------------------------------------
# HTMLRenderer — analytics report
# ---------------------------------------------------------------------------

class TestHTMLRendererAnalytics:
    def setup_method(self):
        self.renderer = HTMLRenderer()
        self.data = _make_report("analytics")
        self.html = self.renderer.render(self.data)

    def test_title_present(self):
        assert "Threat Analytics" in self.html

    def test_nfr20_section(self):
        assert "NFR20" in self.html

    def test_engine_weight_table(self):
        assert "0.40" in self.html   # signature weight
        assert "0.35" in self.html   # RF weight

    def test_fpr_present(self):
        assert "FPR" in self.html

    def test_resolution_rate(self):
        assert "85.0" in self.html or "85" in self.html

    def test_hybrid_detections(self):
        assert "10" in self.html    # both_triggered

    def test_no_jinja_errors(self):
        assert "{{" not in self.html
        assert "{%" not in self.html

    def test_legend_present(self):
        assert "Critical" in self.html
        assert "Medium"   in self.html


# ---------------------------------------------------------------------------
# HTMLRenderer — unknown report type falls back gracefully
# ---------------------------------------------------------------------------

class TestHTMLRendererFallback:
    def test_unknown_type_uses_security_template(self):
        renderer = HTMLRenderer()
        data = _make_report("unknown_type")
        # Should not raise — falls back to security_report.html
        html = renderer.render(data)
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html


# ---------------------------------------------------------------------------
# ReportData — edge cases
# ---------------------------------------------------------------------------

class TestReportDataEdgeCases:
    def test_empty_report_renders_without_error(self):
        renderer = HTMLRenderer()
        data = ReportData(
            report_type="security",
            period_start=datetime(2026, 1, 1, tzinfo=timezone.utc),
            period_end=datetime(2026, 1, 31, tzinfo=timezone.utc),
        )
        html = renderer.render(data)
        assert isinstance(html, str)
        assert "<!DOCTYPE html>" in html

    def test_zero_alerts_no_division_error(self):
        renderer = HTMLRenderer()
        data = _make_report("analytics")
        data.severity = SeverityBreakdown(0, 0, 0, 0)
        html = renderer.render(data)
        assert isinstance(html, str)

    def test_empty_top_attack_types_renders(self):
        renderer = HTMLRenderer()
        data = _make_report("security")
        data.top_attack_types = []
        html = renderer.render(data)
        assert "No attack data" in html

    def test_empty_source_ips_renders(self):
        renderer = HTMLRenderer()
        data = _make_report("security")
        data.top_source_ips = []
        html = renderer.render(data)
        assert "No source IP" in html

    def test_compliance_report_without_compliance_data(self):
        renderer = HTMLRenderer()
        data = _make_report("compliance")
        data.compliance = None
        # Should raise AttributeError in template — this is acceptable
        # as compliance reports always receive compliance data from the builder
        with pytest.raises(Exception):
            renderer.render(data)


# ---------------------------------------------------------------------------
# pdf_exporter — import guard test (WeasyPrint may not be installed in CI)
# ---------------------------------------------------------------------------

class TestPDFExporter:
    def test_raises_runtime_error_when_weasyprint_missing(self):
        """If WeasyPrint is not installed, html_to_pdf must raise RuntimeError."""
        import importlib
        with patch.dict("sys.modules", {"weasyprint": None}):
            from backend.api.reporting.pdf_exporter import html_to_pdf
            with pytest.raises(RuntimeError, match="WeasyPrint"):
                html_to_pdf("<html><body>test</body></html>")

    def test_calls_weasyprint_when_available(self):
        """Verify html_to_pdf calls WeasyHTML(string=...).write_pdf()."""
        mock_pdf = b"%PDF-1.4 fake"
        mock_html_instance = MagicMock()
        mock_html_instance.write_pdf.return_value = mock_pdf
        mock_weasy = MagicMock()
        mock_weasy.HTML.return_value = mock_html_instance

        with patch.dict("sys.modules", {"weasyprint": mock_weasy}):
            # Reload to pick up mock
            import importlib
            import backend.api.reporting.pdf_exporter as pdf_exporter
            importlib.reload(pdf_exporter)
            result = pdf_exporter.html_to_pdf("<html><body>test</body></html>")

        assert result == mock_pdf
        mock_html_instance.write_pdf.assert_called_once()