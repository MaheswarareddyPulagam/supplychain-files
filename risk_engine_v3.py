#!/usr/bin/env python3
"""
SupplyGuard AI - Risk Engine V3

Finding-driven, context-aware engineering risk scoring for npm dependency
updates. The score is a transparent policy score on 0-100, not a probability.

Inputs:
  1) package-level feature CSV (V2/V3 compatible) for successful update rows
  2) localized findings CSV from Feature Extraction V3

The labels in the feature CSV are carried to the output for evaluation only;
they are never used by the scoring function.
"""

from __future__ import annotations

import argparse
import csv
from collections import defaultdict
from pathlib import Path
from typing import Any


# Base policy weights by finding type. These are deliberately conservative for
# generic APIs and stronger for lifecycle/process/obfuscation indicators.
SIGNAL_POINTS: dict[str, float] = {
    "new_postinstall": 45.0,
    "new_preinstall": 45.0,
    "new_prepare": 40.0,
    "new_install": 40.0,
    "npm_targeted_script_changed": 18.0,

    "new_child_process": 12.0,
    "new_spawn": 18.0,
    "new_exec": 16.0,
    "new_eval": 18.0,
    "new_dynamic_function": 12.0,

    "new_filesystem": 5.0,
    "new_network": 5.0,
    "new_environment": 4.0,

    "new_base64_decode": 8.0,
    "new_long_base64_strings": 10.0,
    "new_hex_escape_sequences": 7.0,
}

CATEGORY: dict[str, str] = {
    "new_postinstall": "lifecycle",
    "new_preinstall": "lifecycle",
    "new_prepare": "lifecycle",
    "new_install": "lifecycle",
    "npm_targeted_script_changed": "lifecycle",
    "new_child_process": "execution",
    "new_spawn": "execution",
    "new_exec": "execution",
    "new_eval": "execution",
    "new_dynamic_function": "execution",
    "new_filesystem": "system",
    "new_network": "network",
    "new_environment": "environment",
    "new_base64_decode": "obfuscation",
    "new_long_base64_strings": "obfuscation",
    "new_hex_escape_sequences": "obfuscation",
}

CATEGORY_CAPS = {
    "lifecycle": 55.0,
    "execution": 28.0,
    "system": 12.0,
    "network": 12.0,
    "environment": 10.0,
    "obfuscation": 18.0,
}


def as_int(value: str | None, default: int = 0) -> int:
    try:
        return int(float(value or default))
    except (TypeError, ValueError):
        return default


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def path_context(path: str, signal: str) -> tuple[float, str]:
    p = path.lower().replace("\\", "/")

    if p.endswith("package.json"):
        if signal in {
            "new_postinstall", "new_preinstall", "new_prepare",
            "new_install", "npm_targeted_script_changed",
        }:
            return 1.0, "manifest_lifecycle"
        return 0.85, "manifest"

    # Defensive filter for documentation and source maps. V3 extraction already
    # avoids these, but keeping the rule here prevents future noise.
    if p.endswith(".map") or any(token in p for token in ("readme", "/docs/", "/doc/")):
        return 0.0, "non_code_context"

    # Bundled/minified code is useful context, but repeated generated code should
    # contribute less directly to package risk.
    if p.endswith((".min.js", ".min.mjs", ".min.cjs")):
        return 0.25, "minified_distribution"
    if "/dist/" in p or p.startswith("dist/") or "/vendor/" in p or p.startswith("vendor/"):
        return 0.40, "distribution_or_vendor"

    # Build/test/configuration files can legitimately use sensitive APIs.
    build_tokens = ("jakefile", "gulpfile", "gruntfile", "webpack", "rollup", "babel.config", "vite.config")
    if any(token in p for token in build_tokens) and signal not in {
        "new_postinstall", "new_preinstall", "new_prepare", "new_install",
        "npm_targeted_script_changed",
    }:
        return 0.40, "build_configuration"

    test_tokens = ("/test/", "/tests/", "/__tests__/", "/spec/", ".test.", ".spec.", "mock")
    if any(token in p for token in test_tokens) and signal not in {
        "new_postinstall", "new_preinstall", "new_prepare", "new_install",
        "npm_targeted_script_changed",
    }:
        return 0.35, "test_or_mock"

    ext = Path(p).suffix.lower()
    if ext and ext not in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".html", ".htm"}:
        return 0.65, "nonstandard_extension"

    return 1.0, "source_code"


def semantic_multiplier(signal: str, matched_text: str) -> tuple[float, str]:
    """Make the distinction between context APIs and direct security behavior."""
    m = matched_text.lower().strip()

    if signal == "new_child_process":
        if "require(" in m or "require('child_process')" in m or 'require("child_process")' in m:
            return 0.40, "child_process_import"
        if any(token in m for token in (".exec", ".execfile", ".execfilesync", ".spawn", ".fork")):
            return 1.0, "process_execution_api"
        return 0.60, "child_process_reference"

    if signal == "new_filesystem":
        if "require(" in m and "fs" in m:
            return 0.40, "filesystem_import"
        if any(token in m for token in ("readfile", "writefile", "unlink", "rmdir", "mkdir", "chmod", "chown", "createwritestream")):
            return 0.80, "filesystem_operation"
        return 0.60, "filesystem_reference"

    if signal == "new_network":
        if "require(" in m and any(x in m for x in ("http", "https", "net")):
            return 0.40, "network_import"
        if any(token in m for token in ("fetch(", "http.request", "https.request", ".request(")):
            return 1.0, "network_request"
        return 0.60, "network_reference"

    if signal == "new_environment":
        return 0.60, "environment_access"

    if signal in {"new_dynamic_function", "new_eval"}:
        return 1.0, "dynamic_execution"

    if signal in {"new_base64_decode", "new_long_base64_strings", "new_hex_escape_sequences"}:
        return 0.80, "obfuscation_indicator"

    return 1.0, "direct_signal"


def finding_points(f: dict[str, str]) -> tuple[float, str, str]:
    signal = f.get("signal", "")
    if signal not in SIGNAL_POINTS:
        return 0.0, "", ""

    path_mult, path_reason = path_context(f.get("file", ""), signal)
    if path_mult == 0:
        return 0.0, path_reason, path_reason

    sem_mult, sem_reason = semantic_multiplier(signal, f.get("matched_text", ""))
    points = SIGNAL_POINTS[signal] * path_mult * sem_mult
    return points, path_reason, sem_reason


def level_for(score: float) -> tuple[str, str]:
    if score < 20:
        return "LOW", "No strong corroborating security indicators detected."
    if score < 40:
        return "MEDIUM", "Review the highlighted security-relevant changes."
    if score < 60:
        return "HIGH", "Review before adopting; strong or corroborating security-relevant changes are present."
    return "CRITICAL", "Manual security review recommended; multiple strong indicators are present."


def score_package(findings: list[dict[str, str]], feature_row: dict[str, str] | None) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    # Exact duplicate findings are removed. match_count is retained as context,
    # but never multiplied into the risk score.
    deduped: dict[tuple[str, int, int, str], dict[str, str]] = {}
    for f in findings:
        key = (
            f.get("file", ""),
            as_int(f.get("line_start")),
            as_int(f.get("line_end")),
            f.get("signal", ""),
        )
        deduped[key] = f

    # Build per-finding points first so the dashboard can explain every score.
    contribution_rows: list[dict[str, Any]] = []
    for f in deduped.values():
        base_points, path_reason, sem_reason = finding_points(f)
        contribution_rows.append({
            "package": f.get("package", ""),
            "old_version": f.get("old_version", ""),
            "new_version": f.get("new_version", ""),
            "label": f.get("label", ""),
            "file": f.get("file", ""),
            "line_start": f.get("line_start", ""),
            "line_end": f.get("line_end", ""),
            "signal": f.get("signal", ""),
            "snippet": f.get("snippet", ""),
            "matched_text": f.get("matched_text", ""),
            "match_count": f.get("match_count", ""),
            "path_context": path_reason,
            "semantic_context": sem_reason,
            "base_points": round(base_points, 2),
            "adjusted_points": 0.0,
        })

    # Repeated occurrences of the same signal in one file have diminishing
    # returns. Across files, the first file is full weight and later files are
    # discounted. This prevents bundles/refactors from dominating the score.
    grouped: defaultdict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    for row in contribution_rows:
        grouped[(row["signal"], row["file"])].append(row)

    file_totals: list[tuple[str, str, float]] = []
    for (signal, file_name), rows in grouped.items():
        rows.sort(key=lambda r: (as_int(r["line_start"]), as_int(r["line_end"])))
        if not rows:
            continue
        total = float(rows[0]["base_points"])
        rows[0]["adjusted_points"] = round(rows[0]["base_points"], 2)
        for row in rows[1:]:
            value = float(row["base_points"]) * 0.25
            row["adjusted_points"] = round(value, 2)
            total += value
        file_totals.append((signal, file_name, total))

    # Cross-file diminishing returns for the same signal.
    by_signal: defaultdict[str, list[tuple[str, str, float]]] = defaultdict(list)
    for item in file_totals:
        by_signal[item[0]].append(item)

    signal_scores: defaultdict[str, float] = defaultdict(float)
    file_scores: defaultdict[str, float] = defaultdict(float)
    for signal, items in by_signal.items():
        items.sort(key=lambda x: x[2], reverse=True)
        for idx, (_, file_name, value) in enumerate(items):
            multiplier = 1.0 if idx == 0 else 0.40
            adjusted = value * multiplier
            signal_scores[signal] += adjusted
            file_scores[file_name] += adjusted

        # Write final adjusted points proportionally back to finding rows in the
        # same signal/file group, without changing the total group contribution.
        for idx, (_, file_name, value) in enumerate(items):
            group_mult = 1.0 if idx == 0 else 0.40
            target_total = value * group_mult
            rows = grouped[(signal, file_name)]
            raw_total = sum(float(r["adjusted_points"]) for r in rows)
            if raw_total <= 0:
                continue
            ratio = target_total / raw_total
            for r in rows:
                r["adjusted_points"] = round(float(r["adjusted_points"]) * ratio, 2)

    # Category caps.
    category_scores: defaultdict[str, float] = defaultdict(float)
    for signal, value in signal_scores.items():
        category_scores[CATEGORY[signal]] += value
    capped = {
        cat: min(value, CATEGORY_CAPS[cat])
        for cat, value in category_scores.items()
    }
    score = sum(capped.values())

    active = {cat for cat, value in capped.items() if value > 0}
    bonuses: list[tuple[str, float]] = []
    if {"lifecycle", "execution"}.issubset(active):
        score += 5.0
        bonuses.append(("lifecycle+execution", 5.0))
    if {"execution", "network"}.issubset(active):
        score += 3.0
        bonuses.append(("execution+network", 3.0))
    if {"execution", "environment"}.issubset(active):
        score += 2.0
        bonuses.append(("execution+environment", 2.0))
    if {"obfuscation", "execution"}.issubset(active):
        score += 3.0
        bonuses.append(("obfuscation+execution", 3.0))
    if len(active) >= 3:
        score += 2.0
        bonuses.append(("three_or_more_categories", 2.0))

    score = min(100.0, round(score, 2))
    level, recommendation = level_for(score)

    # Highest-risk file is based on adjusted localized contributions.
    if file_scores:
        highest_file, highest_points = max(file_scores.items(), key=lambda kv: kv[1])
    else:
        highest_file, highest_points = "", 0.0

    triggered = sorted(signal_scores, key=signal_scores.get, reverse=True)
    primary_category = max(capped, key=capped.get) if capped else "none"
    top_contributions = sorted(signal_scores.items(), key=lambda kv: kv[1], reverse=True)[:8]

    # Representative strongest findings for a compact report field.
    strongest = sorted(
        contribution_rows,
        key=lambda r: float(r["adjusted_points"]),
        reverse=True,
    )[:5]
    finding_summary = " | ".join(
        f"{r['signal']} @ {r['file']}:{r['line_start']} ({float(r['adjusted_points']):.2f})"
        for r in strongest
        if float(r["adjusted_points"]) > 0
    )

    feature_row = feature_row or {}
    result = {
        "risk_score": score,
        "risk_level": level,
        "primary_category": primary_category,
        "triggered_signals": "; ".join(triggered),
        "top_contributions": "; ".join(f"{s}={v:.2f}" for s, v in top_contributions),
        "highest_risk_file": highest_file,
        "highest_file_points": round(highest_points, 2),
        "finding_count": len(deduped),
        "matched_occurrences": sum(as_int(f.get("match_count"), 1) for f in deduped.values()),
        "active_categories": "; ".join(sorted(active)),
        "lines_added_context": as_int(feature_row.get("lines_added")),
        "files_changed_context": as_int(feature_row.get("files_changed")),
        "finding_summary": finding_summary,
        "policy_bonuses": "; ".join(f"{name}={value:.1f}" for name, value in bonuses),
        "recommendation": recommendation,
    }
    return result, contribution_rows


def write_csv(path: Path, rows: list[dict[str, Any]]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        return
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--finding-output", required=False)
    args = parser.parse_args()

    features = read_csv(Path(args.features))
    findings = read_csv(Path(args.findings))

    if not features:
        raise ValueError("Feature CSV is empty.")
    if not findings:
        raise ValueError("Findings CSV is empty.")

    required_features = {"package", "old_version", "new_version", "label", "status"}
    required_findings = {
        "package", "old_version", "new_version", "label", "file",
        "line_start", "line_end", "signal", "snippet", "matched_text",
        "match_count", "source",
    }
    missing_f = sorted(required_features - set(features[0]))
    missing_n = sorted(required_findings - set(findings[0]))
    if missing_f:
        raise ValueError(f"Feature CSV missing columns: {missing_f}")
    if missing_n:
        raise ValueError(f"Findings CSV missing columns: {missing_n}")

    feature_ok = {
        (r["package"], r["old_version"], r["new_version"]): r
        for r in features
        if r.get("status") == "ok"
    }
    groups: defaultdict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for f in findings:
        key = (f["package"], f["old_version"], f["new_version"])
        if key in feature_ok:
            groups[key].append(f)

    results: list[dict[str, Any]] = []
    all_contributions: list[dict[str, Any]] = []
    for key, feature_row in sorted(feature_ok.items()):
        scored, contrib = score_package(groups.get(key, []), feature_row)
        results.append({
            "package": key[0],
            "old_version": key[1],
            "new_version": key[2],
            "label": feature_row.get("label", ""),
            "status": feature_row.get("status", ""),
            **scored,
        })
        all_contributions.extend(contrib)

    output_path = Path(args.output)
    write_csv(output_path, results)
    if args.finding_output:
        write_csv(Path(args.finding_output), all_contributions)

    print("=" * 72)
    print("SUPPLYGUARD — RISK ENGINE V3")
    print("=" * 72)
    print(f"Successful updates scored: {len(results)}")
    print(f"Updates with localized findings: {sum(1 for r in results if r['finding_count'] > 0)}")
    print(f"Total localized findings consumed: {sum(int(r['finding_count']) for r in results)}")
    print("\nRisk-level distribution:")
    level_counts: defaultdict[str, int] = defaultdict(int)
    for r in results:
        level_counts[r["risk_level"]] += 1
    for level in ("LOW", "MEDIUM", "HIGH", "CRITICAL"):
        print(f"  {level}: {level_counts[level]}")

    print("\nTop scored updates:")
    for r in sorted(results, key=lambda r: float(r["risk_score"]), reverse=True)[:15]:
        print(
            f"  {r['package']} {r['old_version']} -> {r['new_version']} | "
            f"label={r['label']} | score={r['risk_score']} | {r['risk_level']} | "
            f"primary={r['primary_category']} | file={r['highest_risk_file']}"
        )

    print("\nPilot cases:")
    for pkg in ("arjson", "buildcheck", "ejs", "esbuild", "git-hooks-list"):
        for r in results:
            if r["package"] == pkg:
                print(
                    f"  {pkg}: score={r['risk_score']} | {r['risk_level']} | "
                    f"findings={r['finding_count']} | categories={r['active_categories']} | "
                    f"signals={r['triggered_signals']}"
                )

    print(f"\nOutput: {output_path}")
    if args.finding_output:
        print(f"Finding contribution output: {Path(args.finding_output)}")
    print("=" * 72)


if __name__ == "__main__":
    main()
