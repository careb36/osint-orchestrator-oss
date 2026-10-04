"""
Exponential backoff with jitter — the one implementation every retry path uses.

Four copies of this formula used to live in the code base (the OpenCTI sink,
the alert retry queue, the OpenCTI outbox, and a comment in config.py), each
with its own attempt numbering and its own cap. They agreed by accident.
"""

from __future__ import annotations

import random


def backoff_delay(
    retry: int,
    *,
    base: float,
    jitter_ratio: float,
    cap: float | None = None,
) -> float:
    """
    Seconds to wait before retry number ``retry`` (0-based: the first retry
    waits ``base``, the second ``2·base``, ...).

    The nominal delay ``base·2^retry`` is multiplied by a uniform factor in
    ``[1 - jitter_ratio, 1 + jitter_ratio]`` so that many rows failing at the
    same instant do not retry in lock-step, then clamped to ``cap`` when one
    is given. Negative inputs are treated as zero.
    """
    base = max(0.0, base)
    jitter_ratio = max(0.0, jitter_ratio)
    retry = max(0, retry)
    delay = base * (2**retry)
    delay *= random.uniform(1.0 - jitter_ratio, 1.0 + jitter_ratio)
    if cap is not None:
        delay = min(delay, cap)
    return max(0.0, delay)
