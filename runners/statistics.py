from __future__ import annotations
import math
from collections import Counter
from typing import Iterable, Sequence

def raw_label_counts(labels: Iterable[str]) -> dict[str, int]:
    return dict(sorted(Counter(labels).items()))

def wilson_95(successes: int, total: int) -> tuple[float | None, float | None]:
    if total < 0 or successes < 0 or successes > total:
        raise ValueError("require 0 <= successes <= total")
    if total == 0:
        return None, None
    z = 1.959963984540054
    estimate = successes / total
    denominator = 1 + z * z / total
    center = (estimate + z * z / (2 * total)) / denominator
    half = z * math.sqrt(estimate * (1 - estimate) / total + z * z / (4 * total * total)) / denominator
    return center - half, center + half


def _log_comb(n: int, k: int) -> float:
    if k < 0 or k > n:
        return -math.inf
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def _logsumexp(values: list[float]) -> float:
    if not values:
        return -math.inf
    maximum = max(values)
    return maximum + math.log(sum(math.exp(value - maximum) for value in values))


def finite_population_95(successes: int, sample_size: int, population_size: int) -> tuple[float | None, float | None]:
    """Exact equal-tailed 95% interval under simple random sampling without replacement."""
    if population_size < 0 or sample_size < 0 or sample_size > population_size:
        raise ValueError("require 0 <= sample_size <= population_size")
    if successes < 0 or successes > sample_size:
        raise ValueError("require 0 <= successes <= sample_size")
    if sample_size == 0 or population_size == 0:
        return None, None
    if sample_size == population_size:
        estimate = successes / population_size
        return estimate, estimate
    alpha = 0.025
    log_denominator = _log_comb(population_size, sample_size)
    accepted = []
    minimum_total = successes
    maximum_total = population_size - (sample_size - successes)
    for total_successes in range(minimum_total, maximum_total + 1):
        low_x = max(0, sample_size - (population_size - total_successes))
        high_x = min(sample_size, total_successes)
        logs = {
            observed: _log_comb(total_successes, observed)
            + _log_comb(population_size - total_successes, sample_size - observed)
            - log_denominator
            for observed in range(low_x, high_x + 1)
        }
        lower = math.exp(_logsumexp([value for observed, value in logs.items() if observed <= successes]))
        upper = math.exp(_logsumexp([value for observed, value in logs.items() if observed >= successes]))
        if lower >= alpha and upper >= alpha:
            accepted.append(total_successes)
    if not accepted:
        raise RuntimeError("empty hypergeometric confidence set")
    return min(accepted) / population_size, max(accepted) / population_size


def primary_precision(labels: Sequence[str], population_size: int | None = None) -> dict[str, float | int | None]:
    total = len(labels)
    successes = sum(label == "TP_MVSI" for label in labels)
    population = total if population_size is None else population_size
    low, high = finite_population_95(successes, total, population)
    resolved = [label for label in labels if label != "INSUFFICIENT_EVIDENCE"]
    resolved_successes = sum(label == "TP_MVSI" for label in resolved)
    return {
        "audited_structural_buckets": total,
        "population_structural_buckets": population,
        "tp_mvsi": successes,
        "conservative_lower_bound": successes / total if total else None,
        "finite_population_95_low": low,
        "finite_population_95_high": high,
        "insufficient_evidence": total - len(resolved),
        "resolved_case_precision": resolved_successes / len(resolved) if resolved else None,
        "resolved_case_denominator": len(resolved),
    }

def agreement(labels_1: Sequence[str], labels_2: Sequence[str]) -> dict[str, object]:
    if len(labels_1) != len(labels_2):
        raise ValueError("annotation vectors must have equal length")
    classes = sorted(set(labels_1) | set(labels_2))
    matrix = {left: {right: 0 for right in classes} for left in classes}
    for left, right in zip(labels_1, labels_2):
        matrix[left][right] += 1
    total = len(labels_1)
    observed = sum(matrix[label][label] for label in classes) / total if total else None
    if not total:
        kappa = None
    else:
        expected = sum(sum(matrix[label].values()) * sum(matrix[row][label] for row in classes) for label in classes) / (total * total)
        kappa = (observed - expected) / (1 - expected) if expected != 1 else 1.0
    return {"cohen_kappa": kappa, "confusion_matrix": matrix, "n": total, "raw_agreement": observed}

def historical_counts(rows: Sequence[dict[str, object]]) -> dict[str, object]:
    h = sum(row.get("adjudicated_class") == "MV_SI" for row in rows)
    b = sum(row.get("adjudicated_class") == "MV_SI" and row.get("accepted_build") is True for row in rows)
    m = sum(row.get("adjudicated_class") == "MV_SI" and row.get("accepted_build") is True and row.get("semantic_match") is True for row in rows)
    return {"B": b, "H": h, "M": m, "build_coverage": b / h if h else None, "historical_recovery": m / b if b else None}
