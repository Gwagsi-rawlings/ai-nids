"""
AI-NIDS — PDF Exporter
backend/api/reporting/pdf_exporter.py

Converts HTML report strings to PDF bytes using WeasyPrint.
WeasyPrint renders HTML/CSS to PDF identically to a browser print view,
preserving all styling from the Jinja2 templates.

FR Traceability:
    FR12.7  — Export reports to PDF format

Install dependency:
    pip install weasyprint==60.2

April 26, 2026 | Sprint 2, Week 7 | Developer: GWAGSI Rawlings Nshom
"""

from __future__ import annotations

import logging

logger = logging.getLogger("ai-nids.reporting.pdf")


def html_to_pdf(html: str) -> bytes:
    """
    Convert an HTML string to PDF bytes using WeasyPrint.

    Args:
        html: Full HTML document string (as rendered by HTMLRenderer).

    Returns:
        PDF content as bytes, ready to stream as application/pdf.

    Raises:
        RuntimeError: if WeasyPrint is not installed.
        Exception:    propagated from WeasyPrint on render failure.
    """
    try:
        from weasyprint import HTML as WeasyHTML
    except ImportError as exc:
        raise RuntimeError(
            "WeasyPrint is not installed. "
            "Run: pip install weasyprint==60.2"
        ) from exc

    logger.debug("Rendering PDF from HTML (%d chars)", len(html))
    pdf_bytes: bytes = WeasyHTML(string=html).write_pdf()
    logger.debug("PDF rendered: %d bytes", len(pdf_bytes))
    return pdf_bytes
