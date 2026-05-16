"""
AI-NIDS — HTML Report Renderer
backend/api/reporting/html_renderer.py

Renders ReportData into professional HTML using Jinja2 templates.
Supports three report types: security, compliance, analytics.

FR Traceability:
    FR12.1  — Security summary report
    FR12.7  — PDF export (HTML is the intermediate format)
    FR12.8  — CSV export (handled separately)
    FR13.1  — Compliance reporting
    FR13.4  — Audit trail visibility

April 26, 2026 | Sprint 2, Week 7 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

from backend.api.reporting.report_builder import ReportData

# Template directory sits alongside this file
_TEMPLATE_DIR = Path(__file__).parent / "templates"


def _get_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(_TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
    )
    # Custom filters
    env.filters["pct"]       = lambda v: f"{v:.1f}%"
    env.filters["score"]     = lambda v: f"{v:.4f}"
    env.filters["fmt_dt"]    = lambda v: v.strftime("%Y-%m-%d %H:%M UTC") if v else "—"
    env.filters["fmt_date"]  = lambda v: v.strftime("%Y-%m-%d") if hasattr(v, "strftime") else str(v)
    env.filters["severity_colour"] = _severity_colour
    return env


def _severity_colour(severity: str) -> str:
    return {
        "CRITICAL": "#c0392b",
        "HIGH":     "#e67e22",
        "MEDIUM":   "#f1c40f",
        "LOW":      "#3498db",
    }.get(severity.upper(), "#7f8c8d")


class HTMLRenderer:
    """
    Renders a ReportData instance to an HTML string.
    The same HTML is used for in-browser viewing and WeasyPrint PDF conversion.
    """

    def __init__(self):
        self._env = _get_env()

    def render(self, data: ReportData) -> str:
        """Return an HTML string for the given report."""
        template_map = {
            "security":   "security_report.html",
            "compliance": "compliance_report.html",
            "analytics":  "analytics_report.html",
        }
        template_name = template_map.get(data.report_type, "security_report.html")
        template = self._env.get_template(template_name)
        return template.render(
            data=data,
            now=datetime.now(timezone.utc),
            severity_colour=_severity_colour,
        )