"""Build the implementation notes PDF from docs/IMPLEMENTATION_NOTES.md."""

from __future__ import annotations

import re
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm
from reportlab.platypus import (
    ListFlowable,
    ListItem,
    PageBreak,
    Paragraph,
    Preformatted,
    SimpleDocTemplate,
    Spacer,
)


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SOURCE = PROJECT_ROOT / "docs" / "IMPLEMENTATION_NOTES.md"
OUTPUT = PROJECT_ROOT / "output" / "pdf" / "luxcipher-implementation-notes.pdf"


def main() -> None:
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    story = _build_story(SOURCE.read_text(encoding="utf-8"))

    pdf = SimpleDocTemplate(
        str(OUTPUT),
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=1.8 * cm,
        bottomMargin=1.6 * cm,
        title="LuxCipher Implementation Notes",
        author="LuxCipher",
    )
    pdf.build(story, onFirstPage=_draw_footer, onLaterPages=_draw_footer)
    print(OUTPUT)


def _build_story(markdown: str) -> list:
    styles = _styles()
    story = []
    paragraph_lines: list[str] = []
    quote_lines: list[str] = []
    code_lines: list[str] = []
    in_code = False

    def flush_paragraph() -> None:
        nonlocal paragraph_lines
        if paragraph_lines:
            story.append(
                Paragraph(_inline_markup(" ".join(paragraph_lines)), styles["BodyCustom"])
            )
            paragraph_lines = []

    def flush_quote() -> None:
        nonlocal quote_lines
        if quote_lines:
            story.append(Paragraph(_inline_markup(" ".join(quote_lines)), styles["QuoteCustom"]))
            quote_lines = []

    def flush_code() -> None:
        nonlocal code_lines
        if code_lines:
            story.append(Preformatted("\n".join(code_lines), styles["CodeCustom"]))
            code_lines = []

    for raw_line in markdown.splitlines():
        line = raw_line.rstrip()

        if line.startswith("```"):
            if in_code:
                flush_code()
                in_code = False
            else:
                flush_paragraph()
                flush_quote()
                in_code = True
            continue

        if in_code:
            code_lines.append(line)
            continue

        if not line.strip():
            flush_paragraph()
            flush_quote()
            continue

        if line.startswith("# "):
            flush_paragraph()
            flush_quote()
            if story:
                story.append(PageBreak())
            story.append(Paragraph(_inline_markup(line[2:]), styles["DocTitle"]))
            story.append(
                Paragraph("Implementation choices and current architecture", styles["BodyCustom"])
            )
            story.append(Spacer(1, 8))
            continue

        if line.startswith("## "):
            flush_paragraph()
            flush_quote()
            story.append(Paragraph(_inline_markup(line[3:]), styles["Heading2Custom"]))
            continue

        if line.startswith("> "):
            flush_paragraph()
            quote_lines.append(line[2:])
            continue

        if line.startswith("- "):
            flush_paragraph()
            flush_quote()
            item = Paragraph(_inline_markup(line[2:]), styles["BulletCustom"])
            story.append(
                ListFlowable(
                    [ListItem(item, leftIndent=8)],
                    bulletType="bullet",
                    bulletFontName="Helvetica",
                    bulletFontSize=7,
                    leftIndent=14,
                )
            )
            continue

        numbered = re.match(r"^(\d+)\.\s+(.*)$", line)
        if numbered:
            flush_paragraph()
            flush_quote()
            number, text = numbered.groups()
            item = Paragraph(_inline_markup(text), styles["BulletCustom"])
            story.append(
                ListFlowable(
                    [ListItem(item, leftIndent=8)],
                    bulletType="1",
                    start=int(number),
                    leftIndent=16,
                )
            )
            continue

        paragraph_lines.append(line)

    flush_paragraph()
    flush_quote()
    flush_code()
    return story


def _styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="DocTitle",
            parent=styles["Title"],
            fontName="Helvetica-Bold",
            fontSize=24,
            leading=30,
            textColor=colors.HexColor("#172033"),
            spaceAfter=14,
        )
    )
    styles.add(
        ParagraphStyle(
            name="Heading2Custom",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=15,
            leading=19,
            textColor=colors.HexColor("#1f2937"),
            spaceBefore=14,
            spaceAfter=6,
            keepWithNext=True,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BodyCustom",
            parent=styles["BodyText"],
            fontName="Helvetica",
            fontSize=10.0,
            leading=14.0,
            textColor=colors.HexColor("#111827"),
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="BulletCustom",
            parent=styles["BodyCustom"],
            leftIndent=12,
            firstLineIndent=0,
            spaceAfter=3,
        )
    )
    styles.add(
        ParagraphStyle(
            name="QuoteCustom",
            parent=styles["BodyCustom"],
            leftIndent=18,
            rightIndent=10,
            borderPadding=6,
            backColor=colors.HexColor("#f8fafc"),
            textColor=colors.HexColor("#334155"),
        )
    )
    styles.add(
        ParagraphStyle(
            name="CodeCustom",
            parent=styles["Code"],
            fontName="Courier",
            fontSize=8.8,
            leading=11.5,
            leftIndent=8,
            rightIndent=8,
            backColor=colors.HexColor("#f8fafc"),
            borderColor=colors.HexColor("#e2e8f0"),
            borderWidth=0.5,
            borderPadding=6,
            spaceBefore=5,
            spaceAfter=8,
        )
    )
    return styles


def _inline_markup(text: str) -> str:
    escaped = escape(text)
    return re.sub(r"`([^`]+)`", r'<font name="Courier">\1</font>', escaped)


def _draw_footer(canvas, doc) -> None:
    canvas.saveState()
    canvas.setFont("Helvetica", 8)
    canvas.setFillColor(colors.HexColor("#64748b"))
    canvas.drawString(2 * cm, 1.25 * cm, "LuxCipher Implementation Notes")
    canvas.drawRightString(A4[0] - 2 * cm, 1.25 * cm, f"Page {doc.page}")
    canvas.restoreState()


if __name__ == "__main__":
    main()
