"""Handling of untrusted text (resource names, tags, log lines, tool results).

Anything collected from an audited environment is DATA. It is never an instruction
to ASA or to the reasoning model. Two controls:

1. `scan_text` flags instruction-like content so a rule can report it.
2. `fence` wraps data for the model in an explicitly labelled, escaped block and
   `sanitize_for_agent` strips flagged strings from what the model sees at all.
"""

from __future__ import annotations

import re

INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p, re.IGNORECASE)
    for p in (
        r"ignore (all |any )?(previous|prior|above) (instructions|rules)",
        r"disregard (the )?(system|previous) (prompt|instructions)",
        r"you are now",
        r"system prompt",
        r"\bact as\b.{0,40}\b(admin|root|auditor)\b",
        r"mark (this|all|every).{0,40}\b(pass|secure|compliant)\b",
        r"do not (report|flag|mention)",
        r"call (the )?\w*(delete|write|grant|assign|update|remove)\w* (tool|function)",
        r"<\s*/?\s*(system|assistant|tool)\s*>",
    )
)

REDACTED = "[REDACTED: instruction-like content in untrusted data]"


def scan_text(text: str) -> list[str]:
    """Return the patterns (as source strings) that match `text`."""
    return [p.pattern for p in INJECTION_PATTERNS if p.search(text)]


def sanitize_for_agent(text: str) -> str:
    return REDACTED if scan_text(text) else text


def fence(label: str, text: str) -> str:
    """Wrap untrusted data so it cannot terminate its own fence."""
    safe = sanitize_for_agent(text).replace("```", "'''").replace("<<<", "< < <").replace(">>>", "> > >")
    return f"<<<UNTRUSTED_DATA label={label!r}\n{safe}\nUNTRUSTED_DATA>>>"
