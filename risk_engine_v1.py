#!/usr/bin/env python3
"""
SupplyGuard AI — Risk Engine V1

Purpose
-------
Turn the existing differential-security feature CSV into a transparent
0–100 SupplyGuard risk index.

Important methodological choices
--------------------------------
1. This is a rule/policy engine, NOT a trained ML classifier.
2. The score is fixed-scale; it is NOT normalized to the maximum row in the
   current dataset.
3. Features that are presence/count signals are treated differently.
4. We intentionally DO NOT score:
      - new_install_script
      - package_json_changed
      - new_lifecycle_scripts
   because the current extractor can make these redundant / non-discriminating.
   The specific new_* lifecycle flags and npm_targeted_script_changed are used.
5. Count features use diminishing returns so large benign packages do not
   automatically become high risk.
6. Synergy bonuses capture combinations that are more concerning than any one
   signal alone.
7. We do not claim the weights or thresholds are statistically calibrated.
   They are an explicit V1 security policy and should be validated against
   a larger, independently labeled update corpus later.

Input
-----
data/supplyguard_security_features.csv

Output
------
data/supplyguard_risk_scores.csv
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path

import numpy as np
import pandas as pd


# ---------------------------------------------------------------------------
# V1 SECURITY POLICY
# ---------------------------------------------------------------------------
# These are engineering weights, not probabilities.
# They are intentionally configurable in one place.

BINARY_WEIGHTS: dict[str, float] = {
    # Lifecycle / package-install behavior
    "new_preinstall": 25.0,
    "new_postinstall": 25.0,
    "new_install": 18.0,
    "new_prepare": 10.0,
    "npm_targeted_script_changed": 8.0,

    # Code/system execution
    "new_child_process": 18.0,
    "new_exec": 16.0,
    "new_spawn": 14.0,
    "new_eval": 12.0,

    # System / data access
    "new_filesystem": 8.0,
    "new_network": 7.0,
    "new_environment": 6.0,

    # Obfuscation / encoded content
    "new_base64_decode": 6.0,
    "new_long_base64_strings": 9.0,
    "new_hex_escape_sequences": 7.0,
}

# Count features: (maximum contribution, practical cap for diminishing returns)
COUNT_WEIGHTS: dict[str, tuple[float, float]] = {
    "new_dynamic_function": (7.0, 12.0),
    "new_exec": (16.0, 8.0),
    "new_spawn": (14.0, 8.0),
    "new_child_process": (18.0, 8.0),
    "new_eval": (12.0, 6.0),
    "new_filesystem": (8.0, 10.0),
    "new_network": (7.0, 12.0),
    "new_environment": (6.0, 10.0),
    "new_base64_decode": (6.0, 6.0),
    "new_long_base64_strings": (9.0, 6.0),
    "new_hex_escape_sequences": (7.0, 6.0),
    "new_dependencies": (6.0, 4.0),
}

# Small supporting contribution. These must never dominate behavioral signals.
STRUCTURAL_WEIGHTS = {
    "files_changed": 3.0,
    "lines_added": 3.0,
    "lines_deleted": 1.0,
    "removed_dependencies": 1.0,
}


REQUIRED_COLUMNS = [
    "package",
    "old_version",
    "new_version",
    "label",
    "status",
    *BINARY_WEIGHTS.keys(),
    *COUNT_WEIGHTS.keys(),
    *STRUCTURAL_WEIGHTS.keys(),
]


def to_number(row: pd.Series, column: str) -> float:
    value = row.get(column, 0)
    if pd.isna(value):
        return 0.0
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(value):
        return 0.0
    return max(0.0, value)


def presence(value: float) -> bool:
    return value > 0.0


def diminishing_return(
    value: float,
    cap: float,
) -> float:
    """Map count >= 0 to [0, 1] with log-style diminishing returns."""
    if value <= 0:
        return 0.0
    cap = max(cap, 1.0)
    return min(math.log1p(value) / math.log1p(cap), 1.0)


def score_row(row: pd.Series) -> dict[str, object]:
    contributions: list[tuple[str, float]] = []
    triggered: list[str] = []

    # 1) Binary security signals.
    for feature, weight in BINARY_WEIGHTS.items():
        value = to_number(row, feature)
        if presence(value):
            contributions.append((feature, weight))
            triggered.append(feature)

    # 2) Count-based signals.
    # Some features appear in both BINARY_WEIGHTS and COUNT_WEIGHTS.
    # Do NOT double-count them: use the larger of their two representations.
    binary_names = set(BINARY_WEIGHTS)

    for feature, (max_points, cap) in COUNT_WEIGHTS.items():
        if feature in binary_names:
            # Binary weight already captures event presence.
            # We add only a small incremental amount for repeated occurrences.
            value = to_number(row, feature)
            if value > 1.0:
                extra = (max_points * 0.20) * diminishing_return(value - 1.0, cap)
                if extra > 0:
                    contributions.append((f"{feature}_repeat", extra))
            continue

        value = to_number(row, feature)
        if value > 0:
            points = max_points * diminishing_return(value, cap)
            contributions.append((feature, points))
            triggered.append(feature)

    # 3) Structural support. Small by design.
    structural_caps = {
        "files_changed": 8.0,
        "lines_added": 100.0,
        "lines_deleted": 100.0,
        "removed_dependencies": 4.0,
    }

    for feature, max_points in STRUCTURAL_WEIGHTS.items():
        value = to_number(row, feature)
        if value > 0:
            points = max_points * diminishing_return(
                value,
                structural_caps[feature],
            )
            contributions.append((feature, points))

    # 4) Combination/synergy bonuses.
    lifecycle = any(
        presence(to_number(row, x))
        for x in (
            "new_preinstall",
            "new_postinstall",
            "new_install",
            "new_prepare",
            "npm_targeted_script_changed",
        )
    )
    execution = any(
        presence(to_number(row, x))
        for x in (
            "new_child_process",
            "new_exec",
            "new_spawn",
            "new_eval",
        )
    )
    network = presence(to_number(row, "new_network"))
    environment = presence(to_number(row, "new_environment"))
    obfuscation = any(
        presence(to_number(row, x))
        for x in (
            "new_base64_decode",
            "new_long_base64_strings",
            "new_hex_escape_sequences",
        )
    )

    if lifecycle and execution:
        contributions.append(("synergy:lifecycle+execution", 10.0))

    if lifecycle and network:
        contributions.append(("synergy:lifecycle+network", 8.0))

    if execution and environment:
        contributions.append(("synergy:execution+environment", 6.0))

    if obfuscation and (network or environment):
        contributions.append(("synergy:obfuscation+exfiltration_context", 7.0))

    raw_score = sum(points for _, points in contributions)
    risk_score = max(0.0, min(100.0, raw_score))

    # Fixed thresholds. Configurable; not statistically calibrated.
    if risk_score < 25:
        risk_level = "LOW"
        recommendation = "ALLOW — no strong security indicators detected."
    elif risk_score < 50:
        risk_level = "MEDIUM"
        recommendation = "REVIEW — inspect the highlighted security changes."
    elif risk_score < 75:
        risk_level = "HIGH"
        recommendation = "REVIEW BEFORE UPDATING — security-relevant changes detected."
    else:
        risk_level = "CRITICAL"
        recommendation = "BLOCK / MANUAL SECURITY REVIEW — multiple strong risk indicators."

    top_contrib = sorted(
        contributions,
        key=lambda item: item[1],
        reverse=True,
    )[:8]

    return {
        "risk_score": round(risk_score, 2),
        "risk_level": risk_level,
        "triggered_signals": "; ".join(triggered),
        "top_contributions": "; ".join(
            f"{name}={points:.2f}"
            for name, points in top_contrib
        ),
        "recommendation": recommendation,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="data/supplyguard_security_features.csv",
    )
    parser.add_argument(
        "--output",
        default="data/supplyguard_risk_scores.csv",
    )
    parser.add_argument(
        "--include-errors",
        action="store_true",
        help="include extraction-error rows; missing security features become 0",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")

    df = pd.read_csv(input_path)

    missing = [
        col for col in REQUIRED_COLUMNS
        if col not in df.columns
    ]
    if missing:
        raise ValueError(
            "Missing required columns:\n"
            + "\n".join(f"- {c}" for c in missing)
        )

    if not args.include_errors:
        df = df[df["status"].eq("ok")].copy()

    if df.empty:
        raise ValueError("No analyzable rows remain after status filtering.")

    scored = df.apply(score_row, axis=1, result_type="expand")
    result = pd.concat(
        [
            df[
                [
                    "package",
                    "old_version",
                    "new_version",
                    "label",
                    "status",
                ]
            ].reset_index(drop=True),
            scored.reset_index(drop=True),
        ],
        axis=1,
    )

    # Useful evaluation summary — without claiming ML accuracy.
    print("=" * 72)
    print("SUPPLYGUARD — RISK ENGINE V1")
    print("=" * 72)
    print(f"Rows scored: {len(result)}")
    print("\nRisk-level distribution:")
    print(result["risk_level"].value_counts().sort_index().to_string())

    print("\nTop 15 scored updates:")
    print(
        result[
            [
                "package",
                "old_version",
                "new_version",
                "label",
                "risk_score",
                "risk_level",
            ]
        ]
        .sort_values("risk_score", ascending=False)
        .head(15)
        .to_string(index=False)
    )

    arjson = result[
        (result["package"].eq("arjson"))
        & (result["old_version"].eq("0.1.3"))
        & (result["new_version"].eq("0.1.4"))
    ]

    if not arjson.empty:
        print("\nARJSON PILOT CASE:")
        print(
            arjson[
                [
                    "package",
                    "old_version",
                    "new_version",
                    "risk_score",
                    "risk_level",
                    "triggered_signals",
                    "top_contributions",
                    "recommendation",
                ]
            ].to_string(index=False)
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(output_path, index=False)

    print(f"\nOutput: {output_path}")
    print("=" * 72)


if __name__ == "__main__":
    main()
