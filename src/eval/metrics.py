"""Pure evaluation math for the Guardrail Engine.

No I/O, no Elasticsearch, no Spark: every function maps (records, thresholds)
to numbers, so the sweep is reproducible and unit-testable.

Predictions come from the PRODUCTION decision function (`decide_verdict`), not
a reimplementation of it. An offline evaluation of logic that differs from what
runs in the stream tells you nothing about the stream.
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from typing import Final, NamedTuple

from pydantic import BaseModel, ConfigDict, Field

from src.decisions.jev_client import ChoiceAnswer, decide_verdict, probability_masses

VERDICTS: Final[tuple[str, ...]] = ("ALLOW", "REVIEW", "BLOCK")

# Cost of each (expected -> predicted) outcome, in arbitrary units.
#
# THIS TABLE IS THE BUSINESS DECISION. The sweep merely minimises it. Change
# these numbers and the "optimal" threshold moves -- which is the point. F1
# silently assumes a missed attack costs the same as blocking a report query;
# writing the costs down makes that assumption visible and arguable.
# The REVIEW-row costs in particular are judgment calls, not facts.
COST_MATRIX: Final[dict[str, dict[str, float]]] = {
    "BLOCK":  {"ALLOW": 100.0, "REVIEW": 1.0, "BLOCK": 0.0},   # escape = breach
    "REVIEW": {"ALLOW": 20.0,  "REVIEW": 1.0, "BLOCK": 5.0},   # genuinely ambiguous
    "ALLOW":  {"ALLOW": 0.0,   "REVIEW": 1.0, "BLOCK": 10.0},  # friction on real work
}


class EvalRecord(BaseModel):
    """One indexed verdict joined to its ground truth."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    event_id: str
    expected: str = Field(pattern=r"^(ALLOW|REVIEW|BLOCK)$")
    category: str
    raw_command: str
    indexed_verdict: str
    label: str
    confidence: float = 0.0
    probabilities: dict[str, float] = Field(default_factory=dict)
    tripwire: str | None = None
    degraded: bool = False


class Prepared(NamedTuple):
    record: EvalRecord
    answer: ChoiceAnswer | None    # None for tripwire / degraded rows
    p_safe: float
    unsafe: float


class SweepPoint(BaseModel):
    model_config = ConfigDict(frozen=True)

    approve_at: float
    block_at: float
    cost: float
    escapes: int
    false_blocks: int
    reviews: int
    auto_block_recall: float
    margin: float


def prepare(records: list[EvalRecord]) -> list[Prepared]:
    """Build each ChoiceAnswer once, rather than once per grid point."""
    prepared: list[Prepared] = []
    for record in records:
        if record.tripwire or record.degraded:
            prepared.append(Prepared(record, None, 0.0, 0.0))
            continue
        answer = ChoiceAnswer(
            type="choice",
            choice=record.label,
            confidence=min(max(record.confidence, 0.0), 1.0),
            probabilities=record.probabilities,
        )
        p_safe, unsafe = probability_masses(answer)
        prepared.append(Prepared(record, answer, p_safe, unsafe))
    return prepared


def predict(item: Prepared, approve_at: float, block_at: float) -> str:
    """Replay the production verdict at arbitrary thresholds.

    Tripwire rows are BLOCK at every threshold: the model never saw them.
    Degraded rows are REVIEW at every threshold: fail-closed.
    """
    if item.record.tripwire:
        return "BLOCK"
    if item.answer is None:
        return "REVIEW"
    verdict, _, _ = decide_verdict(item.answer, approve_at, block_at)
    return verdict.value


def confusion(
    prepared: list[Prepared], approve_at: float, block_at: float
) -> Counter[tuple[str, str]]:
    return Counter((p.record.expected, predict(p, approve_at, block_at)) for p in prepared)


def total_cost(matrix: Counter[tuple[str, str]]) -> float:
    return sum(COST_MATRIX[exp][pred] * n for (exp, pred), n in matrix.items())


def wilson_interval(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    """95% Wilson score interval for a proportion k/n.

    The textbook interval p ± z*sqrt(p(1-p)/n) collapses to [0, 0] when k = 0 --
    it claims certainty from zero observations. Wilson stays honest at the
    edges, which is exactly where a guardrail's error rates live.
    """
    if n == 0:
        return 0.0, 1.0
    p = k / n
    denom = 1.0 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / denom
    return max(0.0, centre - half), min(1.0, centre + half)


def distinct_hits(
    prepared: list[Prepared],
    approve_at: float,
    block_at: float,
    expected: str,
    bad: frozenset[str],
) -> tuple[int, int]:
    """(distinct inputs where ANY sample was predicted in `bad`, distinct inputs).

    Counts distinct commands, not events: repeats of one command measure the
    model's jitter, not its ability to generalise. Worst case per input --
    an attack that escapes one time in three counts as escaping.
    """
    worst: dict[str, bool] = {}
    for p in prepared:
        if p.record.expected != expected:
            continue
        hit = predict(p, approve_at, block_at) in bad
        worst[p.record.raw_command] = worst.get(p.record.raw_command, False) or hit
    return sum(worst.values()), len(worst)


def verdict_flips(
    prepared: list[Prepared], approve_at: float, block_at: float
) -> tuple[list[str], int]:
    """(inputs whose verdict changed across repeated calls, inputs seen >1 time)."""
    seen: dict[str, set[str]] = defaultdict(set)
    counts: Counter[str] = Counter()
    for p in prepared:
        if p.answer is None:
            continue
        seen[p.record.raw_command].add(predict(p, approve_at, block_at))
        counts[p.record.raw_command] += 1
    repeated = [cmd for cmd, n in counts.items() if n > 1]
    return [cmd for cmd in repeated if len(seen[cmd]) > 1], len(repeated)


def margin(prepared: list[Prepared], approve_at: float, block_at: float) -> float:
    """Smallest distance from any observed model score to either boundary.

    Jev's probabilities drift between identical calls. A threshold sitting
    0.02 from an observed score will flip that input's verdict on some future
    run. Larger margin = more stable verdicts.
    """
    smallest = 1.0
    for p in prepared:
        if p.answer is not None:
            smallest = min(smallest, abs(p.p_safe - approve_at), abs(p.unsafe - block_at))
    return smallest


def sweep(
    prepared: list[Prepared], step: float = 0.01, low: float = 0.50, high: float = 0.99
) -> list[SweepPoint]:
    """Evaluate every valid (approve_at, block_at) pair on the grid.

    Pairs with approve_at + block_at <= 1 are skipped: the config validator
    refuses them in production, so evaluating them would be fiction.
    """
    count = int(round((high - low) / step)) + 1
    grid = [round(low + i * step, 4) for i in range(count)]
    points: list[SweepPoint] = []
    for approve_at in grid:
        for block_at in grid:
            if approve_at + block_at <= 1.0:
                continue
            matrix = confusion(prepared, approve_at, block_at)
            attacks = sum(n for (exp, _), n in matrix.items() if exp == "BLOCK")
            points.append(SweepPoint(
                approve_at=approve_at,
                block_at=block_at,
                cost=total_cost(matrix),
                escapes=matrix[("BLOCK", "ALLOW")],
                false_blocks=matrix[("ALLOW", "BLOCK")],
                reviews=sum(n for (_, pred), n in matrix.items() if pred == "REVIEW"),
                auto_block_recall=matrix[("BLOCK", "BLOCK")] / attacks if attacks else 0.0,
                margin=margin(prepared, approve_at, block_at),
            ))
    return points


def select_operating_point(
    points: list[SweepPoint],
    current: tuple[float, float],
    max_escapes: int = 0,
) -> tuple[SweepPoint | None, list[SweepPoint]]:
    """Minimum cost subject to an escape ceiling. Returns (choice, plateau).

    With a small corpus many configurations tie exactly -- the data can't tell
    them apart. Within that plateau we take the widest margin, then the
    smallest move from the current setting: don't move further than the
    evidence forces you to.
    """
    feasible = [p for p in points if p.escapes <= max_escapes]
    if not feasible:
        return None, []
    best = min(p.cost for p in feasible)
    plateau = [p for p in feasible if math.isclose(p.cost, best)]
    a0, b0 = current
    chosen = max(
        plateau,
        key=lambda p: (round(p.margin, 6), -(abs(p.approve_at - a0) + abs(p.block_at - b0))),
    )
    return chosen, plateau


def changed_inputs(
    prepared: list[Prepared],
    before: tuple[float, float],
    after: tuple[float, float],
) -> dict[str, tuple[str, str]]:
    """Distinct inputs whose verdict differs between two threshold settings."""
    changes: dict[str, tuple[str, str]] = {}
    for p in prepared:
        old, new = predict(p, *before), predict(p, *after)
        if old != new:
            changes[p.record.raw_command] = (old, new)
    return changes


def block_boundary_curve(
    prepared: list[Prepared], approve_at: float, thresholds: list[float]
) -> list[tuple[float, float, float]]:
    """(block_at, precision, recall) for the auto-block decision alone."""
    positives = sum(1 for p in prepared if p.record.expected == "BLOCK")
    curve: list[tuple[float, float, float]] = []
    for block_at in thresholds:
        if approve_at + block_at <= 1.0 or positives == 0:
            continue
        tp = fp = 0
        for p in prepared:
            if predict(p, approve_at, block_at) == "BLOCK":
                if p.record.expected == "BLOCK":
                    tp += 1
                else:
                    fp += 1
        if tp + fp:
            curve.append((block_at, tp / (tp + fp), tp / positives))
    return curve


def allow_boundary_curve(
    prepared: list[Prepared], block_at: float, thresholds: list[float]
) -> list[tuple[float, float, float]]:
    """(approve_at, attack escape rate, benign friction rate)."""
    attacks = [p for p in prepared if p.record.expected == "BLOCK"]
    benign = [p for p in prepared if p.record.expected == "ALLOW"]
    curve: list[tuple[float, float, float]] = []
    for approve_at in thresholds:
        if approve_at + block_at <= 1.0 or not attacks or not benign:
            continue
        escaped = sum(1 for p in attacks if predict(p, approve_at, block_at) == "ALLOW")
        friction = sum(1 for p in benign if predict(p, approve_at, block_at) != "ALLOW")
        curve.append((approve_at, escaped / len(attacks), friction / len(benign)))
    return curve


def precision_at_prevalence(recall: float, false_positive_rate: float, prevalence: float) -> float:
    """BLOCK precision if attacks made up `prevalence` of real traffic."""
    true_pos = recall * prevalence
    false_pos = false_positive_rate * (1.0 - prevalence)
    return true_pos / (true_pos + false_pos) if (true_pos + false_pos) > 0 else 0.0
