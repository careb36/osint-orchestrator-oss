"""
Make model- and internet-derived text inert before it reaches an operator.

The synthesizer's prompt is built from data scraped off the internet, and its
output is rendered into Markdown reports, PDF, alert e-mails and the console.
A TXT record or a profile bio can therefore end up as a clickable link in a
report or as raw HTML in a renderer. Nothing here changes the meaning of the
text; it only removes the ways text can act instead of being read.
"""

from __future__ import annotations

import re

_LINK = re.compile(r"!?\[([^\]]*)\]\(\s*([^)\s]*)(?:\s+\"[^\"]*\")?\s*\)")
_AUTOLINK = re.compile(r"<((?:https?|ftp|mailto):[^>\s]+)>")
_HTML_TAG = re.compile(r"</?[A-Za-z][^<>]*>")
_HEADING = re.compile(r"^(\s*)(#{1,6})(?=\s)", re.MULTILINE)
_SCHEME = re.compile(r"\b(h)ttp(s?)://", re.IGNORECASE)
# Every separator str.splitlines() honours. A heading after a lone "\r" or a
# "\u2028" is not at a line start for the regexes above, yet a reader that
# splits lines (or reads the file back with universal newlines) sees one.
_LINE_BREAK = re.compile(r"\r\n|[\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")


def neutralise_markdown(text: str) -> str:
    """
    Return *text* with Markdown links and images flattened to ``text (url)``,
    autolinks unwrapped, HTML tags removed, line-leading headings escaped and
    every ``http(s)://`` defanged to ``hxxp(s)://`` — the CTI convention, so a
    URL in an analyst's report is never one click away from being visited.
    Every line break is normalised to ``\n`` first, so no heading hides behind
    a separator the heading escape would not see.
    """
    text = _LINE_BREAK.sub("\n", text)
    text = _LINK.sub(lambda m: f"{m.group(1)} ({m.group(2)})" if m.group(2) else m.group(1), text)
    text = _AUTOLINK.sub(r"\1", text)
    text = _HTML_TAG.sub("", text)
    text = _HEADING.sub(r"\1\\\2", text)
    return _SCHEME.sub(r"\1xxp\2://", text)


def flatten_untrusted(value: str) -> str:
    """
    Prepare an internet-derived value for inclusion inside the prompt's
    UNTRUSTED DATA block: one line, no backticks (they delimit values in the
    prompt) and no way to spell the block's own END marker.
    """
    flat = " ".join(str(value).split())
    return flat.replace("`", "'").replace("UNTRUSTED DATA", "UNTRUSTED-DATA")
