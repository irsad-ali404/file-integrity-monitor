#!/usr/bin/env python3
"""
File Integrity Monitor (FIM)
A defensive cybersecurity project for monitoring changes to files.

Usage:
  python fim.py baseline <directory>
  python fim.py scan <directory>
  python fim.py show-baseline
"""

from __future__ import annotations

import argparse
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

BASELINE_FILE = Path(".fim_baseline.json")
DEFAULT_EXCLUDES = {".git", "__pycache__", ".fim_baseline.json"}


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def collect_files(directory: Path) -> dict[str, str]:
    directory = directory.resolve()
    results: dict[str, str] = {}

    for path in directory.rglob("*"):
        if not path.is_file():
            continue
        if any(part in DEFAULT_EXCLUDES for part in path.parts):
            continue

        relative = path.relative_to(directory).as_posix()
        try:
            results[relative] = sha256_file(path)
        except (PermissionError, OSError) as exc:
            print(f"[!] Could not read {relative}: {exc}")

    return results


def save_baseline(directory: Path, hashes: dict[str, str]) -> None:
    data = {
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "directory": str(directory.resolve()),
        "files": hashes,
    }
    BASELINE_FILE.write_text(json.dumps(data, indent=2), encoding="utf-8")


def load_baseline() -> dict:
    if not BASELINE_FILE.exists():
        raise FileNotFoundError(
            f"{BASELINE_FILE} not found. Run: python fim.py baseline <directory>"
        )
    return json.loads(BASELINE_FILE.read_text(encoding="utf-8"))


def create_baseline(directory: Path) -> None:
    if not directory.is_dir():
        raise NotADirectoryError(directory)

    hashes = collect_files(directory)
    save_baseline(directory, hashes)

    print(f"[+] Baseline created for: {directory.resolve()}")
    print(f"[+] Files hashed: {len(hashes)}")
    print(f"[+] Saved to: {BASELINE_FILE.resolve()}")


def scan(directory: Path) -> None:
    baseline = load_baseline()
    old = baseline["files"]
    current = collect_files(directory)

    added = sorted(set(current) - set(old))
    deleted = sorted(set(old) - set(current))
    modified = sorted(
        path for path in set(old) & set(current) if old[path] != current[path]
    )

    print(f"\nFIM scan: {directory.resolve()}")
    print("-" * 60)

    if not added and not deleted and not modified:
        print("[OK] No changes detected.")
        return

    if added:
        print(f"\n[ADDED] {len(added)} file(s)")
        for path in added:
            print(f"  + {path}")

    if modified:
        print(f"\n[MODIFIED] {len(modified)} file(s)")
        for path in modified:
            print(f"  * {path}")

    if deleted:
        print(f"\n[DELETED] {len(deleted)} file(s)")
        for path in deleted:
            print(f"  - {path}")

    print("\n[!] Review these changes and verify whether they were authorized.")


def show_baseline() -> None:
    baseline = load_baseline()
    print(json.dumps(baseline, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Defensive file integrity monitoring using SHA-256."
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_baseline = sub.add_parser("baseline", help="Create a file-hash baseline.")
    p_baseline.add_argument("directory", type=Path)

    p_scan = sub.add_parser("scan", help="Compare files against the baseline.")
    p_scan.add_argument("directory", type=Path)

    sub.add_parser("show-baseline", help="Display the stored baseline.")

    args = parser.parse_args()

    try:
        if args.command == "baseline":
            create_baseline(args.directory)
        elif args.command == "scan":
            scan(args.directory)
        elif args.command == "show-baseline":
            show_baseline()
    except (FileNotFoundError, NotADirectoryError, json.JSONDecodeError) as exc:
        print(f"[!] {exc}")


if __name__ == "__main__":
    main()
