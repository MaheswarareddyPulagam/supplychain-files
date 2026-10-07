#!/usr/bin/env python3
"""
SupplyGuard AI — Differential Static Feature Extractor

Input:
    supplyguard_analysis_candidates.csv

For each row:
    OLD archive -> NEW archive
    download safely
    read archive members WITHOUT executing anything
    compare file contents and package.json
    extract differential security features

Supported archives:
    .tgz / .tar.gz / .tar
    .zip

Safety:
    - archives are never installed
    - no npm commands
    - no node execution
    - lifecycle scripts are only READ as text
    - archive paths are validated against traversal
    - archive/file size limits are enforced
    - files are analyzed in memory / temporary cache only

Output:
    data/supplyguard_security_features_v3.csv
    data/supplyguard_findings_v3.csv

Important evaluation rule:
    Do NOT randomly split rows if multiple updates from the same package exist.
    Later, split train/test by PACKAGE to reduce leakage.
"""

from __future__ import annotations

import argparse
import csv
import difflib
import hashlib
import io
import json
import os
import re
import shutil
import sys
import tarfile
import tempfile
import time
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.parse import urlparse


USER_AGENT = "SupplyGuardAI-StaticAnalyzer/1.0"

MAX_ARCHIVE_BYTES = 30 * 1024 * 1024
MAX_FILE_BYTES = 8 * 1024 * 1024
MAX_FILES = 6000
DOWNLOAD_TIMEOUT = 90

TEXT_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".json", ".yaml", ".yml", ".txt", ".md",
    ".html", ".css", ".sh", ".bash", ".py",
    ".xml", ".toml", ".ini", ".conf",
}

# Security patterns are applied only to executable/source-like files.
# Documentation, changelogs, source maps, CSS, and arbitrary JSON can contain
# URLs or ordinary JavaScript examples without representing runtime behavior.
CODE_EXTENSIONS = {
    ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx",
    ".vue", ".svelte",
}

SECURITY_PATTERNS = {
    # High-level module/import indicator.
    "child_process": re.compile(
        r"(?:require\(\s*['\"]child_process['\"]\s*\)|"
        r"from\s+['\"]child_process['\"]|"
        r"\bchild_process\b)",
        re.I,
    ),

    # Restrict command-execution calls to explicit child_process usage.
    # This avoids treating RegExp.prototype.exec(...) as shell execution.
    "exec": re.compile(
        r"(?:\bchild_process\s*\.\s*"
        r"exec(?:FileSync|File|Sync)?|"
        r"require\(\s*['\"]child_process['\"]\s*\)"
        r"\s*\.\s*exec(?:FileSync|File|Sync)?)\s*\(",
        re.I,
    ),

    "spawn": re.compile(
        r"(?:\bchild_process\s*\.\s*"
        r"spawn(?:Sync)?|"
        r"require\(\s*['\"]child_process['\"]\s*\)"
        r"\s*\.\s*spawn(?:Sync)?)\s*\(",
        re.I,
    ),

    "eval": re.compile(r"\beval\s*\(", re.I),

    # IMPORTANT: case-sensitive on purpose.
    # Lowercase `function (` is a normal function declaration/callback,
    # not JavaScript's dynamic Function constructor.
    "dynamic_function": re.compile(
        r"\b(?:new\s+Function|Function)\s*\("
    ),

    "filesystem": re.compile(
        r"(?:require\(\s*['\"]fs['\"]\s*\)|"
        r"from\s+['\"]fs(?:/promises)?['\"]|"
        r"\bfs\.(?:readFile|writeFile|unlink|rm|mkdir|rename|copyFile|chmod))",
        re.I,
    ),

    # Network API usage only. A documentation URL or a string literal
    # is not by itself evidence that code performs network I/O.
    "network": re.compile(
        r"(?:require\(\s*['\"](?:http|https|net|tls)['\"]\s*\)|"
        r"from\s+['\"](?:http|https|net|tls)['\"]|"
        # Fetch calls are useful, but exclude a `function fetch(...)` declaration.
        r"(?<!function\s)\bfetch\s*\(|"
        r"\b(?:globalThis|window|self)\s*\.\s*fetch\s*\(|"
        r"\baxios\s*\.\s*(?:request|get|post|put|delete|patch)\s*\(|"
        r"\b(?:https?|http)\.(?:request|get)\s*\(|"
        r"\bnet\.(?:connect|createConnection)\s*\(|"
        r"\btls\.(?:connect|createConnection)\s*\(|"
        r"\bnew\s+XMLHttpRequest\s*\()",
        re.I,
    ),

    "environment": re.compile(
        r"\bprocess\.env\b",
        re.I,
    ),

    # Decode only. btoa() encodes to base64, so it is not a decode signal.
    "base64_decode": re.compile(
        r"(?:atob\s*\(|"
        r"Buffer\.from\s*\([^,]+,\s*['\"]base64['\"])",
        re.I,
    ),
}

INSTALL_SCRIPT_NAMES = {
    "preinstall",
    "install",
    "postinstall",
    "prepare",
}


def request_bytes(url: str) -> bytes:
    req = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "*/*",
        },
    )

    with urlopen(
        req,
        timeout=DOWNLOAD_TIMEOUT,
    ) as response:

        content_length = response.headers.get(
            "Content-Length"
        )

        if content_length:
            try:
                if int(content_length) > MAX_ARCHIVE_BYTES:
                    raise ValueError(
                        f"archive exceeds {MAX_ARCHIVE_BYTES // (1024*1024)} MB limit"
                    )
            except ValueError:
                # If header is malformed, continue and enforce limit while reading.
                pass

        chunks = []
        total = 0

        while True:
            chunk = response.read(1024 * 1024)

            if not chunk:
                break

            total += len(chunk)

            if total > MAX_ARCHIVE_BYTES:
                raise ValueError(
                    f"archive exceeded {MAX_ARCHIVE_BYTES // (1024*1024)} MB limit"
                )

            chunks.append(chunk)

        return b"".join(chunks)


def safe_member_name(name: str) -> str | None:
    # Convert Windows backslashes to URL/archive-style separators.
    name = name.replace("\\", "/").strip()

    if not name or name.endswith("/"):
        return None

    if name.startswith("/") or name.startswith("\\"):
        return None

    # Reject drive prefixes such as C:/...
    if re.match(r"^[A-Za-z]:/", name):
        return None

    parts = []

    for part in name.split("/"):
        if part in {"", "."}:
            continue

        if part == "..":
            return None

        parts.append(part)

    if not parts:
        return None

    # npm packages normally use package/...; remove only that harmless wrapper.
    if parts[0].lower() == "package":
        parts = parts[1:]

    if not parts:
        return None

    return "/".join(parts)


def is_text(path: str, data: bytes) -> bool:
    suffix = Path(path).suffix.lower()

    if suffix in TEXT_EXTENSIONS:
        return b"\x00" not in data

    if b"\x00" in data:
        return False

    try:
        data.decode("utf-8")
        return True
    except UnicodeDecodeError:
        return False


def decode_text(data: bytes) -> str | None:
    if b"\x00" in data:
        return None

    try:
        return data.decode("utf-8")
    except UnicodeDecodeError:
        try:
            return data.decode("utf-8", errors="replace")
        except Exception:
            return None


def read_tar(data: bytes) -> dict[str, bytes]:
    files = {}

    with tarfile.open(
        fileobj=io.BytesIO(data),
        mode="r:*",
    ) as archive:

        members = archive.getmembers()

        if len(members) > MAX_FILES:
            raise ValueError(
                f"archive contains {len(members)} members; limit is {MAX_FILES}"
            )

        for member in members:

            if not member.isfile():
                continue

            safe_name = safe_member_name(
                member.name
            )

            if not safe_name:
                continue

            if member.size > MAX_FILE_BYTES:
                continue

            extracted = archive.extractfile(member)

            if extracted is None:
                continue

            content = extracted.read(
                MAX_FILE_BYTES + 1
            )

            if len(content) > MAX_FILE_BYTES:
                continue

            files[safe_name] = content

    return files


def read_zip(data: bytes) -> dict[str, bytes]:
    files = {}

    with zipfile.ZipFile(
        io.BytesIO(data)
    ) as archive:

        infos = archive.infolist()

        if len(infos) > MAX_FILES:
            raise ValueError(
                f"archive contains {len(infos)} members; limit is {MAX_FILES}"
            )

        for info in infos:

            if info.is_dir():
                continue

            safe_name = safe_member_name(
                info.filename
            )

            if not safe_name:
                continue

            if info.file_size > MAX_FILE_BYTES:
                continue

            with archive.open(info) as stream:
                content = stream.read(
                    MAX_FILE_BYTES + 1
                )

            if len(content) > MAX_FILE_BYTES:
                continue

            files[safe_name] = content

    return files


def read_archive(data: bytes) -> dict[str, bytes]:
    # Try tar first; then zip.
    try:
        return read_tar(data)
    except (tarfile.ReadError, EOFError):
        pass

    try:
        return read_zip(data)
    except zipfile.BadZipFile:
        pass

    raise ValueError(
        "unsupported or malformed archive"
    )


def download_archive(
    url: str,
    cache_dir: Path,
) -> tuple[Path, str]:

    parsed = urlparse(url)

    if parsed.scheme not in {
        "http",
        "https",
    }:
        raise ValueError(
            f"unsupported URL scheme: {parsed.scheme}"
        )

    digest = hashlib.sha256(
        url.encode("utf-8")
    ).hexdigest()

    filename = (
        digest[:24]
        + "_"
        + os.path.basename(
            parsed.path
        )
    )

    cache_path = (
        cache_dir / filename
    )

    if not cache_path.exists():
        data = request_bytes(url)

        tmp = cache_path.with_suffix(
            cache_path.suffix + ".tmp"
        )

        tmp.write_bytes(data)

        tmp.replace(cache_path)

    file_hash = hashlib.sha256(
        cache_path.read_bytes()
    ).hexdigest()

    return (
        cache_path,
        file_hash,
    )


def select_package_json(
    files: dict[str, bytes],
) -> tuple[str | None, dict | None]:

    candidates = []

    for path, data in files.items():

        if Path(path).name.lower() != "package.json":
            continue

        text = decode_text(data)

        if text is None:
            continue

        try:
            manifest = json.loads(text)
        except Exception:
            continue

        if isinstance(manifest, dict):
            candidates.append(
                (path, manifest)
            )

    if not candidates:
        return None, None

    # Prefer a shallow top-level manifest.
    candidates.sort(
        key=lambda x: (
            x[0].count("/"),
            x[0],
        )
    )

    return candidates[0]


def manifest_dependencies(
    manifest: dict | None,
) -> set[str]:

    if not manifest:
        return set()

    result = set()

    for field in (
        "dependencies",
        "devDependencies",
        "optionalDependencies",
        "peerDependencies",
    ):

        value = manifest.get(
            field,
            {}
        )

        if isinstance(value, dict):
            result.update(
                str(k)
                for k in value.keys()
            )

    return result


def manifest_scripts(
    manifest: dict | None,
) -> dict[str, str]:

    if not manifest:
        return {}

    scripts = manifest.get(
        "scripts",
        {}
    )

    if not isinstance(
        scripts,
        dict,
    ):
        return {}

    return {
        str(k): str(v)
        for k, v in scripts.items()
    }


def changed_lines(
    old_text: str | None,
    new_text: str | None,
) -> tuple[int, int, str]:

    if old_text is None:
        old_lines = []
    else:
        old_lines = old_text.splitlines()

    if new_text is None:
        new_lines = []
    else:
        new_lines = new_text.splitlines()

    added = 0
    deleted = 0
    additions = []

    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        lineterm="",
    )

    for line in diff:

        if line.startswith("+++"):
            continue

        if line.startswith("---"):
            continue

        if line.startswith("+"):
            added += 1
            additions.append(
                line[1:]
            )

        elif line.startswith("-"):
            deleted += 1

    return (
        added,
        deleted,
        "\n".join(additions),
    )


def is_security_code_file(path: str) -> bool:
    return Path(path).suffix.lower() in CODE_EXTENSIONS


def security_signal_counts(
    added_text: str,
) -> dict[str, int]:

    counts = {}

    for name, pattern in SECURITY_PATTERNS.items():
        counts[
            f"new_{name}"
        ] = len(
            pattern.findall(
                added_text
            )
        )

    # Basic obfuscation indicators.
    counts["new_long_base64_strings"] = len(
        re.findall(
            r"['\"][A-Za-z0-9+/]{80,}={0,2}['\"]",
            added_text,
        )
    )

    counts["new_hex_escape_sequences"] = len(
        re.findall(
            r"(?:\\x[0-9a-fA-F]{2}){4,}",
            added_text,
        )
    )

    return counts


def added_line_records(
    old_text: str | None,
    new_text: str | None,
) -> list[tuple[int, str]]:
    """
    Return (new-version line number, added/replaced line text) records.

    The records are derived from the same old-vs-new line comparison used for
    aggregate security features. A replacement is represented by its new
    lines, matching unified-diff semantics.
    """
    old_lines = [] if old_text is None else old_text.splitlines()
    new_lines = [] if new_text is None else new_text.splitlines()

    records: list[tuple[int, str]] = []

    matcher = difflib.SequenceMatcher(
        a=old_lines,
        b=new_lines,
        autojunk=False,
    )

    for tag, _i1, _i2, j1, j2 in matcher.get_opcodes():
        if tag not in {"insert", "replace"}:
            continue

        for j in range(j1, j2):
            records.append((j + 1, new_lines[j]))

    return records


def security_findings_for_file(
    path: str,
    old_text: str | None,
    new_text: str | None,
) -> list[dict[str, str]]:
    """
    Locate each security-pattern hit on a line introduced by the update.

    One finding is emitted per signal/file/line. This keeps the output simple,
    deterministic, and directly usable by the risk engine, RAG context builder,
    and frontend localization layer.
    """
    findings: list[dict[str, str]] = []

    if not is_security_code_file(path):
        return findings

    for line_no, line in added_line_records(old_text, new_text):
        for name, pattern in SECURITY_PATTERNS.items():
            matches = [m.group(0) for m in pattern.finditer(line)]
            if matches:
                unique_matches = list(dict.fromkeys(matches))
                findings.append(
                    {
                        "file": path,
                        "line_start": str(line_no),
                        "line_end": str(line_no),
                        "signal": f"new_{name}",
                        "snippet": line.strip()[:500],
                        "matched_text": "; ".join(
                            x[:100] for x in unique_matches[:5]
                        ),
                        "match_count": str(len(matches)),
                        "source": "code_diff",
                    }
                )

        # Obfuscation indicators are line-oriented here as well.
        if re.search(
            r"['\"][A-Za-z0-9+/]{80,}={0,2}['\"]",
            line,
        ):
            findings.append(
                {
                    "file": path,
                    "line_start": str(line_no),
                    "line_end": str(line_no),
                    "signal": "new_long_base64_strings",
                    "snippet": line.strip()[:500],
                    "matched_text": "long_base64_string",
                    "match_count": "1",
                    "source": "code_diff",
                }
            )

        if re.search(
            r"(?:\\x[0-9a-fA-F]{2}){4,}",
            line,
        ):
            findings.append(
                {
                    "file": path,
                    "line_start": str(line_no),
                    "line_end": str(line_no),
                    "signal": "new_hex_escape_sequences",
                    "snippet": line.strip()[:500],
                    "matched_text": "hex_escape_sequence",
                    "match_count": "1",
                    "source": "code_diff",
                }
            )

    return findings


def manifest_key_location(
    manifest_text: str | None,
    key: str,
) -> tuple[int, str] | None:
    """Find a JSON object key such as \"preinstall\" in package.json."""
    if not manifest_text:
        return None

    pattern = re.compile(
        rf"['\"]{re.escape(key)}['\"]\s*:",
        re.I,
    )

    for index, line in enumerate(
        manifest_text.splitlines(),
        start=1,
    ):
        if pattern.search(line):
            return index, line.strip()[:500]

    return None


def manifest_findings(
    old_manifest_path: str | None,
    old_manifest_text: str | None,
    new_manifest_path: str | None,
    new_manifest_text: str | None,
    old_scripts: dict[str, str],
    new_scripts: dict[str, str],
    new_install_scripts: set[str],
) -> list[dict[str, str]]:
    """Create line-localized findings for lifecycle-script changes."""
    findings: list[dict[str, str]] = []

    for name in sorted(new_install_scripts):
        location = manifest_key_location(new_manifest_text, name)
        if location:
            line_no, snippet = location
            findings.append(
                {
                    "file": new_manifest_path or "package.json",
                    "line_start": str(line_no),
                    "line_end": str(line_no),
                    "signal": f"new_{name}",
                    "snippet": snippet,
                    "matched_text": name,
                    "match_count": "1",
                    "source": "package_json",
                }
            )

    for name in sorted(INSTALL_SCRIPT_NAMES):
        old_value = old_scripts.get(name, "")
        new_value = new_scripts.get(name, "")
        if old_value == new_value:
            continue

        location = manifest_key_location(new_manifest_text, name)
        source_file = new_manifest_path
        if location is None:
            location = manifest_key_location(old_manifest_text, name)
            source_file = old_manifest_path

        if location:
            line_no, snippet = location
        else:
            line_no, snippet = 0, f'"{name}": <changed script>'

        findings.append(
            {
                "file": source_file or "package.json",
                "line_start": str(line_no),
                "line_end": str(line_no),
                "signal": "npm_targeted_script_changed",
                "snippet": snippet,
                "matched_text": name,
                "match_count": "1",
                "source": "package_json",
            }
        )

    return findings


def analyze_pair(
    row: dict[str, str],
    cache_dir: Path,
) -> tuple[dict[str, str], list[dict[str, str]]]:

    package = row.get(
        "package",
        "",
    )

    old_version = row.get(
        "old_version",
        "",
    )

    new_version = row.get(
        "new_version",
        "",
    )

    old_url = row.get(
        "old_url",
        "",
    ).strip()

    new_url = row.get(
        "chosen_new_url",
        "",
    ).strip()

    result = dict(row)
    findings: list[dict[str, str]] = []

    try:
        old_path, old_hash = (
            download_archive(
                old_url,
                cache_dir,
            )
        )

        new_path, new_hash = (
            download_archive(
                new_url,
                cache_dir,
            )
        )

        old_files = read_archive(
            old_path.read_bytes()
        )

        new_files = read_archive(
            new_path.read_bytes()
        )

        old_names = set(
            old_files.keys()
        )

        new_names = set(
            new_files.keys()
        )

        added_files = (
            new_names - old_names
        )

        deleted_files = (
            old_names - new_names
        )

        modified_files = set()

        for path in (
            old_names & new_names
        ):
            if old_files[path] != new_files[path]:
                modified_files.add(path)

        total_added_lines = 0
        total_deleted_lines = 0

        all_added_text_parts = []

        for path in (
            sorted(
                added_files
                | modified_files
            )
        ):

            old_text = (
                decode_text(
                    old_files[path]
                )
                if path in old_files
                else None
            )

            new_text = (
                decode_text(
                    new_files[path]
                )
                if path in new_files
                else None
            )

            if new_text is not None:
                findings.extend(
                    security_findings_for_file(
                        path,
                        old_text,
                        new_text,
                    )
                )

            if (
                new_text is not None
                and (
                    old_text is not None
                    or path in added_files
                )
            ):
                added, deleted, new_content = (
                    changed_lines(
                        old_text,
                        new_text,
                    )
                )

                total_added_lines += added
                total_deleted_lines += deleted

                if new_content and is_security_code_file(path):
                    all_added_text_parts.append(
                        new_content
                    )

        all_added_text = "\n".join(
            all_added_text_parts
        )

        old_manifest_path, old_manifest = (
            select_package_json(
                old_files
            )
        )

        new_manifest_path, new_manifest = (
            select_package_json(
                new_files
            )
        )

        old_manifest_text = (
            decode_text(old_files[old_manifest_path])
            if old_manifest_path and old_manifest_path in old_files
            else None
        )
        new_manifest_text = (
            decode_text(new_files[new_manifest_path])
            if new_manifest_path and new_manifest_path in new_files
            else None
        )

        old_deps = manifest_dependencies(
            old_manifest
        )

        new_deps = manifest_dependencies(
            new_manifest
        )

        old_scripts = manifest_scripts(
            old_manifest
        )

        new_scripts = manifest_scripts(
            new_manifest
        )

        added_deps = new_deps - old_deps
        removed_deps = old_deps - new_deps

        new_install_scripts = (
            set(new_scripts.keys())
            & INSTALL_SCRIPT_NAMES
        ) - (
            set(old_scripts.keys())
            & INSTALL_SCRIPT_NAMES
        )

        findings.extend(
            manifest_findings(
                old_manifest_path,
                old_manifest_text,
                new_manifest_path,
                new_manifest_text,
                old_scripts,
                new_scripts,
                new_install_scripts,
            )
        )

        signals = security_signal_counts(
            all_added_text
        )

        result.update(
            {
                "old_archive_sha256": old_hash,
                "new_archive_sha256": new_hash,

                "old_file_count": str(
                    len(old_files)
                ),
                "new_file_count": str(
                    len(new_files)
                ),

                "files_added": str(
                    len(added_files)
                ),
                "files_modified": str(
                    len(modified_files)
                ),
                "files_deleted": str(
                    len(deleted_files)
                ),
                "files_changed": str(
                    len(
                        added_files
                        | modified_files
                        | deleted_files
                    )
                ),

                "lines_added": str(
                    total_added_lines
                ),
                "lines_deleted": str(
                    total_deleted_lines
                ),

                "new_dependencies": str(
                    len(added_deps)
                ),
                "removed_dependencies": str(
                    len(removed_deps)
                ),

                "old_install_script": str(
                    int(
                        bool(
                            set(
                                old_scripts.keys()
                            )
                            & INSTALL_SCRIPT_NAMES
                        )
                    )
                ),

                "new_install_script": str(
                    int(
                        bool(
                            set(
                                new_scripts.keys()
                            )
                            & INSTALL_SCRIPT_NAMES
                        )
                    )
                ),

                "new_lifecycle_scripts": str(
                    len(
                        new_install_scripts
                    )
                ),

                "package_json_changed": str(
                    int(
                        old_manifest !=
                        new_manifest
                    )
                ),

                "new_postinstall": str(
                    int(
                        "postinstall"
                        in new_install_scripts
                    )
                ),

                "new_preinstall": str(
                    int(
                        "preinstall"
                        in new_install_scripts
                    )
                ),

                "new_prepare": str(
                    int(
                        "prepare"
                        in new_install_scripts
                    )
                ),

                "new_install": str(
                    int(
                        "install"
                        in new_install_scripts
                    )
                ),

                "npm_targeted_script_changed": str(
                    int(
                        any(
                            (
                                old_scripts.get(
                                    name,
                                    ""
                                )
                                != new_scripts.get(
                                    name,
                                    ""
                                )
                            )
                            for name
                            in INSTALL_SCRIPT_NAMES
                        )
                    )
                ),

                "old_manifest_path": (
                    old_manifest_path
                    or ""
                ),
                "new_manifest_path": (
                    new_manifest_path
                    or ""
                ),
            }
        )

        result.update(
            {
                name: str(value)
                for name, value
                in signals.items()
            }
        )

        result["status"] = "ok"
        result["error"] = ""

    except Exception as exc:

        result["status"] = "error"
        result["error"] = (
            f"{type(exc).__name__}: {exc}"
        )

    return result, findings


def main():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--candidates",
        required=True,
        help="path to supplyguard_analysis_candidates.csv",
    )

    parser.add_argument(
        "--output",
        default="data/supplyguard_security_features_v2.csv",
    )

    parser.add_argument(
        "--findings-output",
        default="data/supplyguard_findings.csv",
        help="CSV output containing file/line/security-signal findings",
    )

    parser.add_argument(
        "--per-class",
        type=int,
        default=0,
        help="process this many per class; 0 = all",
    )

    parser.add_argument(
        "--workers",
        type=int,
        default=6,
    )

    parser.add_argument(
        "--cache",
        default="data/archive_cache",
    )

    args = parser.parse_args()

    candidates_path = Path(
        args.candidates
    ).resolve()

    output_path = Path(
        args.output
    ).resolve()

    findings_output_path = Path(
        args.findings_output
    ).resolve()

    cache_dir = Path(
        args.cache
    ).resolve()

    if not candidates_path.exists():
        raise FileNotFoundError(
            candidates_path
        )

    cache_dir.mkdir(
        parents=True,
        exist_ok=True,
    )

    with candidates_path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as f:
        rows = list(
            csv.DictReader(f)
        )

    # Balanced selection if requested.
    if args.per_class > 0:

        positive = [
            r for r in rows
            if r.get("label") == "1"
        ]

        negative = [
            r for r in rows
            if r.get("label") == "0"
        ]

        rng = __import__(
            "random"
        ).Random(42)

        rng.shuffle(positive)
        rng.shuffle(negative)

        rows = (
            positive[: args.per_class]
            + negative[: args.per_class]
        )

    print("=" * 72)
    print("SUPPLYGUARD — DIFFERENTIAL STATIC FEATURE EXTRACTION")
    print("=" * 72)
    print(
        f"Rows selected: {len(rows)}"
    )
    print(
        "No package installation or execution will occur."
    )
    print()

    results = []
    all_findings: list[dict[str, str]] = []

    with ThreadPoolExecutor(
        max_workers=max(
            1,
            args.workers
        )
    ) as executor:

        futures = {
            executor.submit(
                analyze_pair,
                row,
                cache_dir,
            ): row
            for row in rows
        }

        completed = 0

        for future in as_completed(
            futures
        ):

            row = futures[future]

            try:
                result, findings_for_row = future.result()
            except Exception as exc:
                result = dict(row)
                result["status"] = "error"
                result["error"] = str(exc)
                findings_for_row = []

            for finding in findings_for_row:
                finding["package"] = result.get("package", "")
                finding["old_version"] = result.get("old_version", "")
                finding["new_version"] = result.get("new_version", "")
                finding["label"] = result.get("label", "")
                finding["attack_id"] = result.get("attack_id", "")
            all_findings.extend(findings_for_row)
            results.append(result)

            completed += 1

            print(
                f"[{completed}/{len(rows)}] "
                f"{row.get('package','')} "
                f"{row.get('old_version','')} -> "
                f"{row.get('new_version','')} : "
                f"{result.get('status')}"
            )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    # Collect columns dynamically so every feature is retained.
    fields = []

    for row in results:
        for key in row.keys():
            if key not in fields:
                fields.append(key)

    with output_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:

        writer = csv.DictWriter(
            f,
            fieldnames=fields,
            extrasaction="ignore",
        )

        writer.writeheader()
        writer.writerows(results)

    findings_output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    findings_fields = [
        "package",
        "old_version",
        "new_version",
        "label",
        "attack_id",
        "file",
        "line_start",
        "line_end",
        "signal",
        "snippet",
        "matched_text",
        "match_count",
        "source",
    ]

    enriched_findings = sorted(
        all_findings,
        key=lambda item: (
            item.get("package", ""),
            item.get("file", ""),
            int(item.get("line_start", "0") or 0),
            item.get("signal", ""),
            item.get("matched_text", ""),
        ),
    )

    with findings_output_path.open(
        "w",
        encoding="utf-8",
        newline="",
    ) as f:
        writer = csv.DictWriter(
            f,
            fieldnames=findings_fields,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(enriched_findings)

    successful = sum(
        r.get("status") == "ok"
        for r in results
    )

    failed = len(results) - successful

    positive = sum(
        r.get("label") == "1"
        and r.get("status") == "ok"
        for r in results
    )

    negative = sum(
        r.get("label") == "0"
        and r.get("status") == "ok"
        for r in results
    )

    print("\n" + "=" * 72)
    print("FEATURE EXTRACTION COMPLETE")
    print("=" * 72)
    print(
        f"Successful analyses: {successful}"
    )
    print(
        f"Failed analyses: {failed}"
    )
    print(
        f"Successful malicious: {positive}"
    )
    print(
        f"Successful benign: {negative}"
    )
    print(
        f"Output: {output_path}"
    )
    print(
        f"Findings output: {findings_output_path}"
    )
    print(
        f"Localized findings: {len(all_findings)}"
    )
    print(
        "\nArchive cache: "
        f"{cache_dir}"
    )
    print(
        "\nSafety: no npm install, no npm run, no Node execution."
    )
    print(
        "\nNext: build risk scoring and RAG context from the localized findings."
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nStopped.")
        sys.exit(130)
    except Exception as exc:
        print(
            f"\nERROR: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
