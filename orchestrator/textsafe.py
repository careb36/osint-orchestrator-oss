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
# Innermost tags first ("<scr<b>ipt>" holds "<b>"), then anything from "<" to
# the next ">" even across a "<" (an attribute hiding one): over-stripping
# beats leaving a tag behind.
_HTML_TAG = re.compile(r"</?[A-Za-z][^<>]*>")
_HTML_TAG_LOOSE = re.compile(r"</?[A-Za-z][^>]*>")
# What is left and still opens like a tag (an unterminated "<img src=…", as a
# truncated error message carries): no renderer may read it as one.
_TAG_START = re.compile(r"<(?=/?[A-Za-z])")
_HEADING = re.compile(r"^(\s*)(#{1,6})(?=\s)", re.MULTILINE)
_SCHEME = re.compile(r"\b(h)ttp(s?)://", re.IGNORECASE)
# GFM turns a bare "www." into a clickable link as well; defang it the same way.
_WWW = re.compile(r"\b(w)ww\.", re.IGNORECASE)
# A line of only "=" or "-" under a text line is a setext heading, and "---"
# alone a thematic break: structure a model's prose must not add to a report.
_SETEXT_OR_RULE = re.compile(r"^(\s*)(=+|-{1,})\s*$", re.MULTILINE)
# Removing a tag can form a new one from its neighbours ("<scr<b>ipt>" leaves
# "<script>"), so stripping repeats until nothing changes; the bound only
# guards against pathological input, each pass shortens the text.
_MAX_TAG_PASSES = 20
# Every separator str.splitlines() honours. A heading after a lone "\r" or a
# "\u2028" is not at a line start for the regexes above, yet a reader that
# splits lines (or reads the file back with universal newlines) sees one.
_LINE_BREAK = re.compile(r"\r\n|[\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029]")


def _strip_tags(text: str) -> str:
    """Remove HTML tags until none is left, including ones removal re-forms."""
    for pattern in (_HTML_TAG, _HTML_TAG_LOOSE):
        for _ in range(_MAX_TAG_PASSES):
            stripped = pattern.sub("", text)
            if stripped == text:
                break
            text = stripped
    return _TAG_START.sub("‹", text)


def neutralise_markdown(text: str) -> str:
    """
    Return *text* with Markdown links and images flattened to ``text (url)``,
    autolinks unwrapped, HTML tags removed (repeatedly, so a tag re-formed by
    the removal of an inner one goes too), ATX and setext headings and
    thematic breaks escaped, and every ``http(s)://`` and bare ``www.``
    defanged to ``hxxp(s)://`` / ``wxw.`` — the CTI convention, so a URL in an
    analyst's report is never one click away from being visited. Every line
    break is normalised to ``\n`` first, so no heading hides behind a
    separator the heading escape would not see.
    """
    text = _LINE_BREAK.sub("\n", text)
    text = _LINK.sub(lambda m: f"{m.group(1)} ({m.group(2)})" if m.group(2) else m.group(1), text)
    text = _AUTOLINK.sub(r"\1", text)
    text = _strip_tags(text)
    text = _HEADING.sub(r"\1\\\2", text)
    text = _SETEXT_OR_RULE.sub(r"\1\\\2", text)
    text = _WWW.sub(r"\1xw.", text)
    return _SCHEME.sub(r"\1xxp\2://", text)


def flatten_untrusted(value: str) -> str:
    """
    Prepare an internet-derived value for inclusion inside the prompt's
    UNTRUSTED DATA block: one line, no backticks (they delimit values in the
    prompt) and no way to spell the block's own END marker.
    """
    flat = " ".join(str(value).split())
    return flat.replace("`", "'").replace("UNTRUSTED DATA", "UNTRUSTED-DATA")
