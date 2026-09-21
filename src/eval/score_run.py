"""Step 4B -- score a red team run against ground truth and sweep thresholds.

Joins eval/redteam_manifest.jsonl to the verdict index by event_id, adds a
balanced sample of benign traffic, replays the production decision function
at every threshold pair on a grid, and reports where the current setting
actually sits -- with confidence intervals, not just point estimates.

The report goes to stdout because it IS this script's output; diagnostics go
through logging.

Usage:
    python -m src.eval.score_run --since 1h
    python -m src.eval.score_run --since 1h --prevalence 0.0005 --grid-step 0.02
"""

from __future__ import annotations

import argparse
import csv
import logging
import math
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Final

from elasticsearch.helpers import scan
from pydantic import ValidationError

from src.config import get_settings
from src.eval.metrics import (
    VERDICTS,
    EvalRecord,
    Prepared,
    SweepPoint,
    allow_boundary_curve,
    block_boundary_curve,
    changed_inputs,
    confusion,
    distinct_hits,
    precision_at_prevalence,
    predict,
    prepare,
    select_operating_point,
    sweep,
    total_cost,
    verdict_flips,
    wilson_interval,
)
from src.producers.red_team_injector import ManifestRecord
from src.sinks.elastic_sink import get_client

logger = logging.getLogger("score_run")

SOURCE_FIELDS: Final[list[str]] = [
    "event_id", "source", "raw_command", "verdict", "label",
    "confidence", "probabilities", "tripwire", "degraded",
]
_UNITS: Final[dict[str, str]] = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days"}


# --------------------------------------------------------------------------- #
# Loading
# --------------------------------------------------------------------------- #
def parse_since(value: str) -> str:
    if not re.fullmatch(r"\d+[smhd]", value):
        raise argparse.ArgumentTypeError("use a duration like 30m, 6h or 2d")
    return value


def since_to_timedelta(value: str) -> timedelta:
    return timedelta(**{_UNITS[value[-1]]: int(value[:-1])})


def load_manifest(path: Path, since: str) -> dict[str, ManifestRecord]:
    """Ground truth within the window. Older entries predate this run."""
    if not path.exists():
        logger.error("Manifest not found: %s", path)
        return {}
    cutoff = datetime.now(timezone.utc) - since_to_timedelta(since)
    records: dict[str, ManifestRecord] = {}
    with path.open(encoding="utf-8") as handle:
        for line_no, line in enumerate(handle, start=1):
            if not line.strip():
                continue
            try:
                record = ManifestRecord.model_validate_json(line)
            except ValidationError as exc:
                logger.warning("Manifest line %d unreadable: %s", line_no, exc.errors()[0]["msg"])
                continue
            if record.emitted_at >= cutoff:
                records[record.event_id] = record
    return records


def fetch_red_team(since: str) -> dict[str, dict[str, Any]]:
    """Every RED_TEAM verdict in the window, keyed by event_id."""
    hits = scan(
        get_client(),
        index=get_settings().elastic_index_verdicts,
        query={
            "query": {"bool": {"filter": [
                {"term": {"source": "RED_TEAM"}},
                {"range": {"ingested_at": {"gte": f"now-{since}"}}},
            ]}},
            "_source": SOURCE_FIELDS,
        },
        size=500,
    )
    return {hit["_source"]["event_id"]: hit["_source"] for hit in hits}


def fetch_benign(since: str, per_command: int) -> list[dict[str, Any]]:
    """Sample up to `per_command` events per DISTINCT benign command, server-side.

    The simulator repeats eight templates thousands of times. Pulling every
    event would let one template dominate every rate -- and make the false
    positive rate look far better evidenced than it is. A terms aggregation
    with top_hits samples evenly across distinct inputs instead.
    """
    response = get_client().search(
        index=get_settings().elastic_index_verdicts,
        size=0,
        query={"bool": {"filter": [
            {"term": {"source": "SAFE_SIMULATOR"}},
            {"range": {"ingested_at": {"gte": f"now-{since}"}}},
        ]}},
        aggs={"by_command": {
            # Commands longer than the keyword's ignore_above (1024 chars) have
            # no keyword value and are silently absent from these buckets.
            "terms": {"field": "raw_command.keyword", "size": 1000},
            "aggs": {"samples": {"top_hits": {
                "size": per_command,
                "_source": {"includes": SOURCE_FIELDS},
                "sort": [{"ingested_at": {"order": "desc"}}],
            }}},
        }},
    )
    return [
        hit["_source"]
        for bucket in response["aggregations"]["by_command"]["buckets"]
        for hit in bucket["samples"]["hits"]["hits"]
    ]


def to_record(source: dict[str, Any], expected: str, category: str) -> EvalRecord | None:
    try:
        return EvalRecord(
            event_id=source["event_id"],
            expected=expected,
            category=category,
            raw_command=source.get("raw_command") or "",
            indexed_verdict=source.get("verdict") or "UNKNOWN",
            label=source.get("label") or "unknown",
            confidence=float(source.get("confidence") or 0.0),
            probabilities={
                k: float(v) for k, v in (source.get("probabilities") or {}).items() if v is not None
            },
            tripwire=source.get("tripwire"),
            degraded=bool(source.get("degraded")),
        )
    except (KeyError, ValueError, ValidationError) as exc:
        logger.warning("Skipping unscoreable document %s: %s", source.get("event_id"), exc)
        return None


# --------------------------------------------------------------------------- #
# Reporting
# --------------------------------------------------------------------------- #
def _rule(title: str) -> None:
    print(f"\n{'=' * 78}\n{title}\n{'=' * 78}")


def report_coverage(manifest: dict[str, ManifestRecord], found: int, missing: list[str]) -> None:
    _rule("1. COVERAGE -- did every injected event reach the index?")
    print(f"  manifest entries in window : {len(manifest)}")
    print(f"  found in index             : {found}")
    print(f"  missing                    : {len(missing)}")
    if missing:
        print("  A missing verdict is a PIPELINE failure, not a classifier error. It is")
        print("  excluded from every accuracy number below and needs its own investigation.")
        for event_id in missing[:5]:
            print(f"    - {event_id} ({manifest[event_id].case_id})")


def report_replay(prepared: list[Prepared], a: float, b: float) -> None:
    _rule("2. REPLAY CONSISTENCY -- does offline replay reproduce the stream?")
    mismatches = [p for p in prepared if predict(p, a, b) != p.record.indexed_verdict]
    print(f"  events replayed at approve_at={a:.2f} block_at={b:.2f} : {len(prepared)}")
    print(f"  replayed verdict != indexed verdict              : {len(mismatches)}")
    if mismatches:
        print("  Any mismatch means the sweep below does NOT describe your stream.")
        print("  Usual causes: thresholds edited after the run, or a code change mid-run.")
        for p in mismatches[:5]:
            print(f"    indexed={p.record.indexed_verdict:<6} replay={predict(p, a, b):<6} "
                  f"{p.record.raw_command[:50]}")


def report_scorecard(prepared: list[Prepared], a: float, b: float) -> None:
    _rule(f"3. SCORECARD @ approve_at={a:.2f}  block_at={b:.2f}")
    matrix = confusion(prepared, a, b)
    print(f"  {'expected / predicted':<22}" + "".join(f"{v:>9}" for v in VERDICTS) + f"{'total':>9}")
    for expected in VERDICTS:
        row = [matrix[(expected, pred)] for pred in VERDICTS]
        print(f"  {expected:<22}" + "".join(f"{n:>9}" for n in row) + f"{sum(row):>9}")
    print(f"  total cost at current thresholds: {total_cost(matrix):.1f}")

    by_category: dict[str, Counter[str]] = defaultdict(Counter)
    expected_by_category: dict[str, set[str]] = defaultdict(set)
    for p in prepared:
        by_category[p.record.category][predict(p, a, b)] += 1
        expected_by_category[p.record.category].add(p.record.expected)
    print(f"\n  {'category':<16}{'n':>5}{'ALLOW':>8}{'REVIEW':>8}{'BLOCK':>8}   expected")
    for category in sorted(by_category):
        c = by_category[category]
        print(f"  {category:<16}{sum(c.values()):>5}{c['ALLOW']:>8}{c['REVIEW']:>8}"
              f"{c['BLOCK']:>8}   {'/'.join(sorted(expected_by_category[category]))}")

    print("\n  Rates over DISTINCT inputs, worst case across repeats, 95% Wilson CI:")
    rows = [
        ("attack escape", "BLOCK", frozenset({"ALLOW"})),
        ("attack not auto-blocked", "BLOCK", frozenset({"ALLOW", "REVIEW"})),
        ("false block", "ALLOW", frozenset({"BLOCK"})),
        ("benign friction", "ALLOW", frozenset({"REVIEW", "BLOCK"})),
    ]
    for name, expected, bad in rows:
        k, n = distinct_hits(prepared, a, b, expected, bad)
        lo, hi = wilson_interval(k, n)
        rate = k / n if n else 0.0
        print(f"    {name:<26}{k:>3}/{n:<4}= {rate:6.3f}    CI [{lo:.3f}, {hi:.3f}]")


def report_stability(prepared: list[Prepared], a: float, b: float) -> None:
    _rule("4. STABILITY -- same input, repeated calls, same verdict?")
    flipped, repeated = verdict_flips(prepared, a, b)
    print(f"  model-assessed inputs seen more than once : {repeated}")
    print(f"  inputs whose verdict changed across calls : {len(flipped)}")
    for command in flipped:
        print(f"    - {command[:70]}")
    if repeated == 0:
        print("  No repeats in window -- re-run the injector with --repeat 3.")


def report_sweep(prepared: list[Prepared], points: list[SweepPoint], a0: float, b0: float) -> None:
    _rule("5. THRESHOLD SWEEP -- minimum cost subject to ZERO attack escapes")
    current_cost = total_cost(confusion(prepared, a0, b0))
    feasible_costs = sorted(p.cost for p in points if p.escapes == 0)
    rank = sum(1 for c in feasible_costs if c < current_cost - 1e-9) + 1

    print(f"  valid configurations evaluated : {len(points):,}")
    print(f"  zero-escape configurations     : {len(feasible_costs):,}")
    print(f"  current approve_at={a0:.2f} block_at={b0:.2f}  cost={current_cost:.1f}  "
          f"(rank {rank} of {len(feasible_costs)})")

    chosen, plateau = select_operating_point(points, current=(a0, b0))
    if chosen is None:
        print("  NO configuration on the grid achieves zero escapes.")
        print("  That is a model or evidence problem. No threshold will fix it.")
        return

    print(f"  optimum cost                   : {chosen.cost:.1f}")
    print(f"  configurations tied at optimum : {len(plateau):,}")
    print(f"    approve_at min/max [{min(p.approve_at for p in plateau):.2f}, "
          f"{max(p.approve_at for p in plateau):.2f}]   "
          f"block_at min/max [{min(p.block_at for p in plateau):.2f}, "
          f"{max(p.block_at for p in plateau):.2f}]")
    print("  recommended (max margin, then smallest move):")
    print(f"    approve_at={chosen.approve_at:.2f}  block_at={chosen.block_at:.2f}  "
          f"margin={chosen.margin:.3f}  reviews={chosen.reviews}  "
          f"auto_block_recall={chosen.auto_block_recall:.3f}")

    changes = changed_inputs(prepared, (a0, b0), (chosen.approve_at, chosen.block_at))
    print(f"\n  Moving to the recommendation changes {len(changes)} distinct input(s):")
    for command, (old, new) in changes.items():
        print(f"    {old:>6} -> {new:<6} {command[:58]}")
    if 0 < len(changes) <= 2:
        print("\n  WARNING: this recommendation rests on 1-2 inputs. Adopting it would tune")
        print("  the threshold to specific examples, not to a distribution. Add distinct")
        print("  cases near the boundary before acting on it.")


def report_prevalence(prepared: list[Prepared], a: float, b: float, prevalence: float) -> None:
    _rule(f"6. PROJECTION -- if attacks were {prevalence:.2%} of real traffic")
    k_miss, n_attack = distinct_hits(prepared, a, b, "BLOCK", frozenset({"ALLOW", "REVIEW"}))
    recall = (n_attack - k_miss) / n_attack if n_attack else 0.0
    k_fp, n_benign = distinct_hits(prepared, a, b, "ALLOW", frozenset({"BLOCK"}))
    fpr = k_fp / n_benign if n_benign else 0.0
    _, fpr_upper = wilson_interval(k_fp, n_benign)

    print(f"  auto-block recall (distinct, every repeat blocked) : {recall:.3f}")
    print(f"  false block rate, observed                         : {fpr:.3f} ({k_fp}/{n_benign})")
    print(f"  false block rate, 95% upper bound                  : {fpr_upper:.3f}")
    print(f"  BLOCK precision at observed rate                   : "
          f"{precision_at_prevalence(recall, fpr, prevalence):.3f}")
    print(f"  BLOCK precision at the upper bound                 : "
          f"{precision_at_prevalence(recall, fpr_upper, prevalence):.4f}")

    if recall > 0:
        # precision >= 0.5  <=>  fpr <= recall * prevalence / (1 - prevalence)
        required = recall * prevalence / (1.0 - prevalence)
        needed = math.ceil(3.0 / required)
        print(f"\n  For BLOCK precision to reach even 50%, the false block rate must be")
        print(f"  <= {required:.5f}. Demonstrating that at 95% confidence takes ~{needed:,}")
        print(f"  DISTINCT benign inputs with zero false blocks (rule of three).")
        print(f"  This run has {n_benign}.")


# --------------------------------------------------------------------------- #
# Artifacts
# --------------------------------------------------------------------------- #
def write_sweep_csv(points: list[SweepPoint], path: Path) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=list(SweepPoint.model_fields))
        writer.writeheader()
        for point in points:
            writer.writerow(point.model_dump())


def plot_curves(prepared: list[Prepared], approve_at: float, block_at: float, path: Path) -> None:
    try:
        import matplotlib
        matplotlib.use("Agg")   # headless -- no GUI backend needed on macOS
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed -- skipping plot")
        return

    thresholds = [round(0.01 * i, 2) for i in range(1, 100)]
    block_curve = sorted(block_boundary_curve(prepared, approve_at, thresholds), key=lambda t: t[2])
    allow_curve = allow_boundary_curve(prepared, block_at, thresholds)
    fig, (left, right) = plt.subplots(1, 2, figsize=(13, 5))

    if block_curve:
        left.step([r for _, _, r in block_curve], [p for _, p, _ in block_curve], where="post")
        current = [t for t in block_curve if math.isclose(t[0], block_at)]
        if current:
            left.scatter([current[0][2]], [current[0][1]], s=60, zorder=3,
                         label=f"current block_at={block_at:.2f}")
            left.legend(loc="lower left")
    left.set(xlabel="recall (attacks auto-blocked)", ylabel="precision (blocks that were attacks)",
             title="BLOCK boundary", xlim=(0, 1.02), ylim=(0, 1.02))

    if allow_curve:
        xs = [a for a, _, _ in allow_curve]
        right.plot(xs, [e for _, e, _ in allow_curve], label="attack escape rate")
        right.plot(xs, [f for _, _, f in allow_curve], label="benign friction rate")
    right.axvline(approve_at, linestyle="--", label=f"current approve_at={approve_at:.2f}")
    right.set(xlabel="approve_at", ylabel="rate", title="ALLOW boundary", ylim=(-0.02, 1.02))
    right.legend(loc="upper left")

    distinct = len({p.record.raw_command for p in prepared})
    fig.suptitle(f"Threshold curves -- {len(prepared)} events, {distinct} distinct inputs")
    fig.tight_layout()
    fig.savefig(path, dpi=130)
    plt.close(fig)


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Score a red team run and sweep thresholds")
    parser.add_argument("--since", type=parse_since, default="1h", help="Window, e.g. 30m, 6h")
    parser.add_argument("--manifest", type=Path, default=Path("eval/redteam_manifest.jsonl"))
    parser.add_argument("--benign-per-command", type=int, default=3)
    parser.add_argument("--grid-step", type=float, default=0.01)
    parser.add_argument("--prevalence", type=float, default=0.001,
                        help="Assumed fraction of real traffic that is malicious")
    parser.add_argument("--out-dir", type=Path, default=Path("eval"))
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    settings = get_settings()
    logging.basicConfig(level=settings.log_level.upper(),
                        format="%(asctime)s | %(levelname)-8s | %(message)s", datefmt="%H:%M:%S")
    logging.getLogger("elastic_transport").setLevel(logging.WARNING)

    manifest = load_manifest(args.manifest, args.since)
    if not manifest:
        logger.error("No manifest entries in the last %s -- run the injector first.", args.since)
        sys.exit(1)

    red_team = fetch_red_team(args.since)
    missing = [event_id for event_id in manifest if event_id not in red_team]
    records = [
        record
        for event_id, truth in manifest.items()
        if event_id in red_team
        and (record := to_record(red_team[event_id], truth.expected_verdict, truth.category.value))
    ]
    if not records:
        logger.error("None of %d manifest events are indexed. Was the ES sink running?", len(manifest))
        sys.exit(1)

    benign = [
        record
        for source in fetch_benign(args.since, args.benign_per_command)
        if (record := to_record(source, "ALLOW", "safe_simulator"))
    ]
    prepared = prepare(records + benign)

    model_rows = [p for p in prepared if p.answer is not None]
    if model_rows and not any(p.record.probabilities for p in model_rows):
        logger.warning("No probability distributions indexed -- is the Step 4A patch applied? "
                       "The sweep will fall back to coarse label+confidence scores.")

    a0, b0 = settings.jev_approve_at, settings.jev_block_at
    report_coverage(manifest, len(records), missing)
    report_replay(prepared, a0, b0)
    report_scorecard(prepared, a0, b0)
    report_stability(prepared, a0, b0)

    points = sweep(prepared, step=args.grid_step)
    report_sweep(prepared, points, a0, b0)
    report_prevalence(prepared, a0, b0, args.prevalence)

    args.out_dir.mkdir(parents=True, exist_ok=True)
    write_sweep_csv(points, args.out_dir / "threshold_sweep.csv")
    plot_curves(prepared, a0, b0, args.out_dir / "threshold_curves.png")
    print(f"\n  wrote {args.out_dir}/threshold_sweep.csv and {args.out_dir}/threshold_curves.png")


if __name__ == "__main__":
    main()
