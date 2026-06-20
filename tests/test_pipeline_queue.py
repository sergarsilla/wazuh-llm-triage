"""Tests for the bounded work queue that buffers alerts before triage."""

from __future__ import annotations

from src.pipeline import _build_work_queue


def test_default_queue_is_bounded() -> None:
    """With no config, the queue is bounded so a backend stall cannot OOM us."""
    assert _build_work_queue({}).maxsize == 10000


def test_queue_size_is_read_from_config() -> None:
    """The bound is configurable (values arrive as strings after env expansion)."""
    assert _build_work_queue({"max_queue_size": "256"}).maxsize == 256


def test_zero_restores_an_unbounded_queue() -> None:
    """A 0 bound is the explicit escape hatch back to an unbounded queue."""
    assert _build_work_queue({"max_queue_size": 0}).maxsize == 0
