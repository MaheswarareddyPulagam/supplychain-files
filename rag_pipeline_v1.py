#!/usr/bin/env python3
"""
SupplyGuard AI - RAG Security Evidence Pipeline V1

Purpose:
- Read successful SupplyGuard feature rows and localized findings.
- Query OSV for exact npm package versions (old and new).
- Expand OSV IDs into full advisory records.
- Add existing local security-intelligence metadata from the SupplyGuard feature CSV.
- Build a compact, auditable evidence corpus.
- Retrieve top evidence for each analyzed update using a hybrid lexical score.
- Emit JSONL that can be passed to the LLM reasoning layer.

Safety:
- Does not npm-install packages.
- Does not execute package code.
- Only performs read-only HTTP requests to OSV.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import re
import sys
import time
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/{}"
USER_AGENT = "SupplyGuardAI-RAG/1.0"

STOPWORDS = {
    "the", "a", "an", "and", "or", "of", "to", "in", "on", "for", "with",
    "from", "by", "is", "are", "was", "were", "be", "this", "that", "new",
    "old", "version", "package", "change", "changes", "file", "line", "lines",
}

SIGNAL_TERMS = {
    "new_preinstall": {"preinstall", "lifecycle", "install script"},
    "new_postinstall": {"postinstall", "lifecycle", "install script"},
    "new_prepare": {"prepare", "lifecycle", "install script"},
    "new_install": {"install", "lifecycle", "install script"},
    "npm_targeted_script_changed": {"npm", "lifecycle", "install script", "script"},
    "new_child_process": {"child_process", "process", "command", "execution"},
    "new_exec": {"exec", "command", "execution", "process"},
    "new_spawn": {"spawn", "process", "execution"},
    "new_eval": {"eval", "dynamic", "code execution"},
    "new_dynamic_function": {"function", "dynamic", "code execution"},
    "new_filesystem": {"filesystem", "file", "read", "write", "fs"},
    "new_network": {"network", "http", "https", "request", "fetch", "socket"},
    "new_environment": {"environment", "process.env", "secret", "credential"},
    "new_base64_decode": {"base64", "decode", "encoded"},
    "new_long_base64_strings": {"base64", "obfuscation", "encoded"},
    "new_hex_escape_sequences": {"hex", "escape", "obfuscation"},
}


def eprint(*args: Any) -> None:
    print(*args, file=sys.stderr)


def clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    return str(value)


def split_tokens(text: str) -> set[str]:
    tokens = re.findall(r"[a-zA-Z][a-zA-Z0-9_./-]{1,}", text.lower())
    return {t for t in tokens if t not in STOPWORDS and len(t) > 2}


def request_json(url: str, payload: dict[str, Any] | None = None, retries: int = 3) -> dict[str, Any]:
    body = None
    method = "GET"
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json",
    }
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        method = "POST"
        headers["Content-Type"] = "application/json"

    last_error: Exception | None = None
    for attempt in range(retries):
        try:
            req = Request(url, data=body, headers=headers, method=method)
            with urlopen(req, timeout=30) as resp:
                raw = resp.read().decode("utf-8")
                return json.loads(raw)
        except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
            last_error = exc
            if attempt + 1 < retries:
                time.sleep(1.5 * (attempt + 1))
    raise RuntimeError(f"HTTP request failed: {url}\n{last_error}")


def stable_id(*parts: str) -> str:
    data = "\x1f".join(parts).encode("utf-8", errors="replace")
    return hashlib.sha256(data).hexdigest()[:16]


def read_csv(path: Path) -> list[dict[str, str]]:
    with path.open("r", encoding="utf-8-sig", newline="") as fh:
        return list(csv.DictReader(fh))


def build_local_intel_docs(features_rows: list[dict[str, str]]) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    for row in features_rows:
        if row.get("status") != "ok":
            continue

        source = clean_text(row.get("source"))
        attack_id = clean_text(row.get("attack_id"))
        attack_title = clean_text(row.get("attack_title"))
        references = clean_text(row.get("references"))

        # Only ingest rows that actually contain security-intelligence content.
        # Benchmark provenance such as OMCBench is not evidence and is deliberately excluded.
        if not any([attack_id, attack_title, references]):
            continue

        package = clean_text(row.get("package"))
        old_v = clean_text(row.get("old_version"))
        new_v = clean_text(row.get("new_version"))

        text_parts = [
            package,
            f"update {old_v} to {new_v}",
            attack_id,
            attack_title,
            references,
            source,
        ]
        docs.append({
            "doc_id": stable_id("local", package, old_v, new_v, attack_id, attack_title),
            "doc_type": "local_security_intelligence",
            "source": source or "local",
            "title": attack_title or attack_id or f"Security intelligence for {package}",
            "evidence_kind": "known_malicious_package" if attack_id else "security_incident",
            "package": package,
            "version": new_v,
            "old_version": old_v,
            "attack_id": attack_id,
            "references": references,
            "text": "\n".join(p for p in text_parts if p),
        })
    return docs


def query_osv_versions(updates: list[tuple[str, str]], cache_dir: Path, skip_osv: bool) -> dict[tuple[str, str], list[dict[str, Any]]]:
    results: dict[tuple[str, str], list[dict[str, Any]]] = defaultdict(list)
    if skip_osv:
        return results

    cache_dir.mkdir(parents=True, exist_ok=True)
    unique = sorted(set(updates))
    batches = [unique[i:i + 100] for i in range(0, len(unique), 100)]

    for batch_idx, batch in enumerate(batches, 1):
        cache_key = stable_id("querybatch", *[f"{p}@{v}" for p, v in batch])
        cache_path = cache_dir / f"querybatch_{cache_key}.json"

        if cache_path.exists():
            payload = json.loads(cache_path.read_text(encoding="utf-8"))
        else:
            request = {
                "queries": [
                    {
                        "package": {"name": package, "ecosystem": "npm"},
                        "version": version,
                    }
                    for package, version in batch
                ]
            }
            print(f"  OSV query batch {batch_idx}/{len(batches)} ({len(batch)} versions)")
            payload = request_json(OSV_QUERY_BATCH_URL, request)
            cache_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

        response_items = payload.get("results", [])
        for (package, version), item in zip(batch, response_items):
            for vuln in item.get("vulns", []) or []:
                results[(package, version)].append(vuln)

    return results


def expand_osv_details(osv_hits: dict[tuple[str, str], list[dict[str, Any]]], cache_dir: Path, skip_osv: bool) -> list[dict[str, Any]]:
    docs: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    detail_dir = cache_dir / "details"
    if not skip_osv:
        detail_dir.mkdir(parents=True, exist_ok=True)

    for (package, version), hits in sorted(osv_hits.items()):
        for hit in hits:
            vuln_id = clean_text(hit.get("id"))
            if not vuln_id:
                continue
            cache_path = detail_dir / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', vuln_id)}.json"

            try:
                if cache_path.exists():
                    detail = json.loads(cache_path.read_text(encoding="utf-8"))
                else:
                    detail = request_json(OSV_VULN_URL.format(vuln_id))
                    cache_path.write_text(json.dumps(detail, ensure_ascii=False, indent=2), encoding="utf-8")
            except Exception as exc:
                eprint(f"[WARN] Could not expand {vuln_id}: {exc}")
                detail = hit

            doc_key = (vuln_id, package, version)
            if stable_id(*doc_key) in seen_ids:
                continue
            seen_ids.add(stable_id(*doc_key))

            affected = detail.get("affected", []) or []
            references = detail.get("references", []) or []
            aliases = detail.get("aliases", []) or []
            ref_urls = [r.get("url", "") for r in references if isinstance(r, dict)]

            text_parts = [
                vuln_id,
                clean_text(detail.get("summary")),
                clean_text(detail.get("details")),
                "aliases: " + ", ".join(map(str, aliases)),
                "affected package/version: " + f"{package}@{version}",
                "references: " + " ".join(ref_urls),
            ]

            advisory_id_lower = vuln_id.lower()
            evidence_kind = "malicious_package" if advisory_id_lower.startswith("mal-") else "vulnerability_or_advisory"
            docs.append({
                "doc_id": stable_id("osv", vuln_id, package, version),
                "doc_type": "osv_advisory",
                "source": "OSV",
                "title": clean_text(detail.get("summary")) or vuln_id,
                "evidence_kind": evidence_kind,
                "advisory_id": vuln_id,
                "package": package,
                "version": version,
                "aliases": aliases,
                "affected": affected,
                "references": ref_urls,
                "published": clean_text(detail.get("published")),
                "modified": clean_text(detail.get("modified")),
                "text": "\n".join(p for p in text_parts if p.strip()),
            })
    return docs


def package_from_purl(purl: str) -> str:
    if purl.startswith("pkg:npm/"):
        rest = purl[len("pkg:npm/"):]
        if rest.startswith("%40"):
            rest = "@" + rest[3:]
        elif rest.startswith("@"):
            pass
        return rest.split("@", 1)[0]
    return ""


def build_query_text(update: dict[str, str], findings: list[dict[str, str]]) -> str:
    parts = [
        update.get("package", ""),
        update.get("old_version", ""),
        update.get("new_version", ""),
    ]
    for f in findings:
        parts.extend([
            f.get("signal", ""),
            f.get("file", ""),
            f.get("snippet", ""),
            f.get("matched_text", ""),
        ])
    return " ".join(parts)


def evidence_score(query: str, package: str, version: str, doc: dict[str, Any]) -> float:
    q_tokens = split_tokens(query)
    d_text = clean_text(doc.get("text"))
    d_tokens = split_tokens(d_text)
    overlap = len(q_tokens & d_tokens)
    if not q_tokens:
        overlap_ratio = 0.0
    else:
        overlap_ratio = overlap / len(q_tokens)

    score = min(35.0, overlap * 2.5) + overlap_ratio * 35.0

    d_package = clean_text(doc.get("package"))
    d_version = clean_text(doc.get("version"))
    if d_package == package:
        score += 30.0
    if d_version == version:
        score += 20.0

    # Source quality: OSV records have structured advisory metadata.
    if doc.get("doc_type") == "osv_advisory":
        score += 5.0
    elif doc.get("doc_type") == "local_security_intelligence":
        score += 3.0

    return round(score, 4)


def build_contexts(
    feature_rows: list[dict[str, str]],
    findings_rows: list[dict[str, str]],
    evidence_docs: list[dict[str, Any]],
    top_k: int,
    risk_rows: list[dict[str, str]] | None = None,
) -> list[dict[str, Any]]:
    successful = [r for r in feature_rows if r.get("status") == "ok"]
    by_update: dict[tuple[str, str, str], list[dict[str, str]]] = defaultdict(list)
    for finding in findings_rows:
        key = (
            finding.get("package", ""),
            finding.get("old_version", ""),
            finding.get("new_version", ""),
        )
        by_update[key].append(finding)

    risk_map: dict[tuple[str, str, str], dict[str, str]] = {}
    for rr in risk_rows or []:
        risk_map[(rr.get("package", ""), rr.get("old_version", ""), rr.get("new_version", ""))] = rr

    contexts: list[dict[str, Any]] = []
    for row in successful:
        package = row.get("package", "")
        old_v = row.get("old_version", "")
        new_v = row.get("new_version", "")
        key = (package, old_v, new_v)
        findings = by_update.get(key, [])
        query = build_query_text(row, findings)

        ranked = []
        for doc in evidence_docs:
            score = evidence_score(query, package, new_v, doc)
            # Do not surface weak, unrelated corpus records as if they were evidence.
            same_package = clean_text(doc.get("package")) == package
            q_tokens = split_tokens(query)
            d_tokens = split_tokens(clean_text(doc.get("text")))
            overlap = len(q_tokens & d_tokens)
            if score >= 25.0 or (same_package and overlap >= 1):
                ranked.append((score, doc))
        ranked.sort(key=lambda item: (-item[0], item[1].get("doc_id", "")))

        top_docs = []
        for score, doc in ranked[:top_k]:
            top_docs.append({
                "score": score,
                "doc_id": doc.get("doc_id"),
                "doc_type": doc.get("doc_type"),
                "source": doc.get("source"),
                "title": doc.get("title"),
                "advisory_id": doc.get("advisory_id", ""),
                "evidence_kind": doc.get("evidence_kind", "security_intelligence"),
                "package": doc.get("package", ""),
                "version": doc.get("version", ""),
                "published": doc.get("published", ""),
                "modified": doc.get("modified", ""),
                "references": doc.get("references", []),
                "evidence_text": doc.get("text", ""),
            })

        signal_counts = Counter(f.get("signal", "") for f in findings if f.get("signal"))
        contexts.append({
            "package": package,
            "old_version": old_v,
            "new_version": new_v,
            "analysis_query": query,
            "risk_assessment": (
                {
                    "risk_score": risk_map[key].get("risk_score", ""),
                    "risk_level": risk_map[key].get("risk_level", ""),
                    "primary_category": risk_map[key].get("primary_category", ""),
                    "recommendation": risk_map[key].get("recommendation", ""),
                }
                if key in risk_map else None
            ),
            "findings": [
                {
                    "file": f.get("file", ""),
                    "line_start": f.get("line_start", ""),
                    "line_end": f.get("line_end", ""),
                    "signal": f.get("signal", ""),
                    "snippet": f.get("snippet", ""),
                    "matched_text": f.get("matched_text", ""),
                    "match_count": f.get("match_count", ""),
                }
                for f in findings
            ],
            "finding_signal_counts": dict(signal_counts),
            "retrieved_evidence": top_docs,
            "retrieval_note": "Evidence ranking is a transparent lexical baseline; it is not a malware probability.",
        })

    return contexts


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--features", required=True)
    parser.add_argument("--findings", required=True)
    parser.add_argument("--output", default="data/supplyguard_rag_context_v1.jsonl")
    parser.add_argument("--corpus-output", default="data/supplyguard_security_corpus_v1.jsonl")
    parser.add_argument("--risk-scores", default="", help="Optional risk_engine_v3 CSV to include in each RAG context record.")
    parser.add_argument("--osv-cache", default="data/osv_cache")
    parser.add_argument("--top-k", type=int, default=5)
    parser.add_argument("--batch-size", type=int, default=100, help="OSV querybatch size; OSV supports multiple queries per request.")
    parser.add_argument("--skip-osv", action="store_true", help="Build contexts from local security-intelligence metadata only.")
    args = parser.parse_args()

    features_path = Path(args.features)
    findings_path = Path(args.findings)
    output_path = Path(args.output)
    corpus_path = Path(args.corpus_output)
    cache_dir = Path(args.osv_cache)

    if not features_path.exists():
        raise FileNotFoundError(features_path)
    if not findings_path.exists():
        raise FileNotFoundError(findings_path)

    feature_rows = read_csv(features_path)
    findings_rows = read_csv(findings_path)
    risk_rows = read_csv(Path(args.risk_scores)) if args.risk_scores else []

    successful = [r for r in feature_rows if r.get("status") == "ok"]
    updates = []
    for row in successful:
        package = row.get("package", "")
        old_v = row.get("old_version", "")
        new_v = row.get("new_version", "")
        updates.extend([(package, old_v), (package, new_v)])

    print("=" * 72)
    print("SUPPLYGUARD — RAG EVIDENCE PIPELINE V1")
    print("=" * 72)
    print(f"Successful updates: {len(successful)}")
    print(f"Localized findings: {len(findings_rows)}")
    print(f"Unique package-version queries: {len(set(updates))}")

    local_docs = build_local_intel_docs(feature_rows)
    print(f"Local security-intelligence documents: {len(local_docs)}")

    osv_hits = query_osv_versions(updates, cache_dir, args.skip_osv)
    osv_docs = expand_osv_details(osv_hits, cache_dir, args.skip_osv)
    print(f"OSV evidence documents: {len(osv_docs)}")

    # Deduplicate identical document IDs.
    corpus_map = {}
    for doc in local_docs + osv_docs:
        corpus_map[doc["doc_id"]] = doc
    corpus = list(corpus_map.values())

    corpus_path.parent.mkdir(parents=True, exist_ok=True)
    with corpus_path.open("w", encoding="utf-8") as fh:
        for doc in corpus:
            fh.write(json.dumps(doc, ensure_ascii=False) + "\n")

    contexts = build_contexts(feature_rows, findings_rows, corpus, max(1, args.top_k), risk_rows)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8") as fh:
        for ctx in contexts:
            fh.write(json.dumps(ctx, ensure_ascii=False) + "\n")

    print(f"Knowledge corpus: {corpus_path}")
    print(f"RAG contexts: {output_path}")
    print("=" * 72)
    print("Safety: no npm install, no npm run, no Node execution.")


if __name__ == "__main__":
    main()
