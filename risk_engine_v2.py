#!/usr/bin/env python3
"""
SupplyGuard AI — Risk Engine V2

A transparent, fixed-scale policy engine for the current differential
security features.

Design goals
------------
- Do not train or pretend to estimate malware probability.
- Do not normalize scores by the maximum row in the current dataset.
- Do not let large source files or common APIs dominate the score.
- Treat lifecycle-script introduction as a stronger security context.
- Cap broad behavior categories so legitimate packages with many API calls
  do not automatically become critical.
- Add combination bonuses only when different security contexts corroborate.
- Keep the output explainable for the React/RAG/LLM layers.

Important feature semantics from the current extractor
-------------------------------------------------------
- new_preinstall / new_postinstall / new_prepare / new_install:
    newly added lifecycle scripts, because they come from new_install_scripts
    (new lifecycle keys minus old lifecycle keys).
- npm_targeted_script_changed:
    any text change to a recognized lifecycle script, including addition,
    modification, or removal.
- new_install_script:
    presence of a recognized lifecycle script in the NEW manifest. It is
    intentionally excluded from scoring because it is not an introduction.
- package_json_changed:
    intentionally excluded; it is too common to be a discriminating signal.
- new_exec / new_network / new_dynamic_function / etc.:
    counts of matching patterns in lines added by the update. V2 converts
    these to bounded presence/context contributions instead of rewarding raw
    counts directly.

This is V2 of the engineering policy. It is NOT statistically calibrated.
Do not present the score as a probability or as measured accuracy.
"""

from __future__ import annotations

import argparse
import math
from pathlib import Path

import pandas as pd


# ---------------------------------------------------------------------------
# POLICY
# ---------------------------------------------------------------------------

LIFECYCLE_POINTS = {
    "new_preinstall": 45.0,
    "new_postinstall": 45.0,
    "new_install": 20.0,
    "new_prepare": 15.0,
}

EXECUTION_POINTS = {
    "new_child_process": 11.0,
    "new_exec": 10.0,
    "new_spawn": 9.0,
    "new_eval": 8.0,
    "new_dynamic_function": 4.0,
}
EXECUTION_CAP = 22.0

SYSTEM_POINTS = {
    "new_filesystem": 5.0,
    "new_network": 5.0,
    "new_environment": 5.0,
}
SYSTEM_CAP = 12.0

OBFUSCATION_POINTS = {
    "new_base64_decode": 6.0,
    "new_long_base64_strings": 8.0,
    "new_hex_escape_sequences": 5.0,
}
OBFUSCATION_CAP = 12.0

# These are intentionally small supporting contributions.
DEPENDENCY_POINTS = {
    "new_dependencies": 3.0,
    "removed_dependencies": 1.0,
}
STRUCTURAL_POINTS = {
    "files_changed": 2.0,
    "lines_added": 2.0,
    "lines_deleted": 0.5,
}

# A changed lifecycle script that is not a newly introduced script.
TARGETED_SCRIPT_CHANGE_POINTS = 5.0

# Fixed scale:
#   0–24  LOW
#  25–49  MEDIUM
#  50–74  HIGH
#  75–100 CRITICAL


def num(row: pd.Series, name: str) -> float:
    value = row.get(name, 0)
    if pd.isna(value):
        return 0.0
    try:
        value = float(value)
    except (TypeError, ValueError):
        return 0.0
    if not math.isfinite(value):
        return 0.0
    return max(0.0, value)


def present(row: pd.Series, name: str) -> bool:
    return num(row, name) > 0.0


def capped_presence_score(
    row: pd.Series,
    weights: dict[str, float],
    cap: float,
) -> tuple[float, list[tuple[str, float]]]:
    """
    Presence-based category score.

    A count of 1 and a count of 100 both establish that a behavior is present.
    The cap prevents a legitimate large source file from dominating the score.
    """
    contributions = [
        (name, weight)
        for name, weight in weights.items()
        if present(row, name)
    ]
    return min(sum(weight for _, weight in contributions), cap), contributions


def small_log_score(value: float, cap_input: float, max_points: float) -> float:
    if value <= 0:
        return 0.0
    ratio = math.log1p(value) / math.log1p(max(cap_input, 1.0))
    return min(max_points, max_points * ratio)


def score_row(row: pd.Series) -> dict[str, object]:
    contributions: list[tuple[str, float, str]] = []
    triggered: list[str] = []

    # 1. Lifecycle introduction.
    lifecycle_points = 0.0
    lifecycle_signals = []
    for feature, weight in LIFECYCLE_POINTS.items():
        if present(row, feature):
            lifecycle_points += weight
            lifecycle_signals.append(feature)
            triggered.append(feature)

    lifecycle_points = min(lifecycle_points, 60.0)
    for feature in lifecycle_signals:
        contributions.append(
            (feature, LIFECYCLE_POINTS[feature], "lifecycle")
        )

    # A changed lifecycle script deserves a smaller independent contribution.
    # If this is simply the addition already represented above, the contribution
    # remains small and is not allowed to dominate.
    if present(row, "npm_targeted_script_changed"):
        contributions.append(
            ("npm_targeted_script_changed", TARGETED_SCRIPT_CHANGE_POINTS, "lifecycle")
        )
        triggered.append("npm_targeted_script_changed")

    # 2. Code execution behaviors.
    execution_score, execution_contrib = capped_presence_score(
        row,
        EXECUTION_POINTS,
        EXECUTION_CAP,
    )
    for feature, points in execution_contrib:
        contributions.append((feature, points, "execution"))
        triggered.append(feature)

    # 3. System/network behaviors.
    system_score, system_contrib = capped_presence_score(
        row,
        SYSTEM_POINTS,
        SYSTEM_CAP,
    )
    for feature, points in system_contrib:
        contributions.append((feature, points, "system"))
        triggered.append(feature)

    # 4. Obfuscation indicators.
    obfuscation_score, obfuscation_contrib = capped_presence_score(
        row,
        OBFUSCATION_POINTS,
        OBFUSCATION_CAP,
    )
    for feature, points in obfuscation_contrib:
        contributions.append((feature, points, "obfuscation"))
        triggered.append(feature)

    # 5. Small supporting context.
    for feature, max_points in DEPENDENCY_POINTS.items():
        value = num(row, feature)
        if value > 0:
            points = small_log_score(
                value,
                4.0,
                max_points,
            )
            contributions.append((feature, points, "dependency"))

    for feature, max_points in STRUCTURAL_POINTS.items():
        value = num(row, feature)
        if value > 0:
            # Large changes are supporting context, never the main reason for
            # a high score.
            cap_input = 8.0 if feature == "files_changed" else 100.0
            points = small_log_score(
                value,
                cap_input,
                max_points,
            )
            contributions.append((feature, points, "structural"))

    # 6. Corroboration / synergy.
    lifecycle = bool(lifecycle_signals)
    execution = execution_score > 0
    external = (
        present(row, "new_network")
        or present(row, "new_environment")
    )
    obfuscation = obfuscation_score > 0

    if lifecycle and execution:
        contributions.append(
            ("synergy:lifecycle+execution", 10.0, "synergy")
        )

    if lifecycle and external:
        contributions.append(
            ("synergy:lifecycle+network_or_environment", 10.0, "synergy")
        )

    if obfuscation and (execution or external):
        contributions.append(
            ("synergy:obfuscation+behavior", 8.0, "synergy")
        )

    # 7. Final fixed-scale score.
    raw_score = sum(points for _, points, _ in contributions)

    # Keep scoring bounded but NEVER normalize against the dataset maximum.
    risk_score = max(0.0, min(100.0, raw_score))

    if risk_score < 25:
        level = "LOW"
        recommendation = "LOW RISK — no strong security indicators detected."
    elif risk_score < 50:
        level = "MEDIUM"
        recommendation = "REVIEW — inspect the highlighted security-relevant changes."
    elif risk_score < 75:
        level = "HIGH"
        recommendation = "REVIEW BEFORE UPDATING — strong security-relevant changes detected."
    else:
        level = "CRITICAL"
        recommendation = "MANUAL SECURITY REVIEW — multiple corroborating security indicators detected."

    # Primary reason = highest individual contribution.
    ranked = sorted(
        contributions,
        key=lambda item: item[1],
        reverse=True,
    )

    primary_category = ranked[0][2] if ranked else "none"
    top = ranked[:8]

    # Remove duplicate names while preserving order.
    seen = set()
    unique_triggered = []
    for signal in triggered:
        if signal not in seen:
            seen.add(signal)
            unique_triggered.append(signal)

    return {
        "risk_score": round(risk_score, 2),
        "risk_level": level,
        "primary_category": primary_category,
        "triggered_signals": "; ".join(unique_triggered),
        "top_contributions": "; ".join(
            f"{name}={points:.2f}"
            for name, points, _ in top
        ),
        "recommendation": recommendation,
    }


REQUIRED = [
    "package",
    "old_version",
    "new_version",
    "label",
    "status",
    *LIFECYCLE_POINTS.keys(),
    "npm_targeted_script_changed",
    *EXECUTION_POINTS.keys(),
    *SYSTEM_POINTS.keys(),
    *OBFUSCATION_POINTS.keys(),
    *DEPENDENCY_POINTS.keys(),
    *STRUCTURAL_POINTS.keys(),
]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--input",
        default="data/supplyguard_security_features.csv",
    )
    parser.add_argument(
        "--output",
        default="data/supplyguard_risk_scores_v2.csv",
    )
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)

    if not input_path.exists():
        raise FileNotFoundError(f"Input CSV not found: {input_path}")

    df = pd.read_csv(input_path)

    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(
            "Missing required columns:\n" +
            "\n".join(f"- {c}" for c in missing)
        )

    df = df[df["status"].eq("ok")].copy()
    if df.empty:
        raise ValueError("No successful analyses available.")

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

    print("=" * 72)
    print("SUPPLYGUARD — RISK ENGINE V2")
    print("=" * 72)
    print(f"Rows scored: {len(result)}")

    print("\nRisk-level distribution:")
    print(result["risk_level"].value_counts().to_string())

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
                "primary_category",
            ]
        ]
        .sort_values("risk_score", ascending=False)
        .head(15)
        .to_string(index=False)
    )

    print("\nPilot cases:")
    pilots = result[
        result["package"].isin(["arjson", "buildcheck", "ejs"])
    ][
        [
            "package",
            "old_version",
            "new_version",
            "label",
            "risk_score",
            "risk_level",
            "primary_category",
            "triggered_signals",
            "top_contributions",
            "recommendation",
        ]
    ]
    print(pilots.to_string(index=False))

    output_path.parent.mkdir(parents=True, exist_ok=True)
    result.to_csv(output_path, index=False)

    print(f"\nOutput: {output_path}")
    print("=" * 72)


if __name__ == "__main__":
    main()
