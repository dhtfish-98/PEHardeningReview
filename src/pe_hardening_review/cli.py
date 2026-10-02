"""CLI for local PE metadata review."""

from __future__ import annotations

import argparse
import json
from .parser import PEFormatError, inspect_file


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Read declared PE mitigation flags from a local file")
    parser.add_argument("file", help="local PE image you own or are authorized to inspect")
    parser.add_argument("--json", action="store_true", help="emit structured report")
    args = parser.parse_args(argv)
    try:
        report = inspect_file(args.file)
    except PEFormatError as exc:
        parser.error(str(exc))
    if args.json:
        print(json.dumps(report.export(), sort_keys=True))
    else:
        print(f"{report.format} machine={report.machine} sections={report.section_count}")
        print(f"DYNAMIC_BASE declared: {report.dynamic_base_declared}")
        print(f"NX_COMPAT declared: {report.nx_compatible_declared}")
        print(f"GUARD_CF declared: {report.guard_cf_declared}")
        print(f"HIGH_ENTROPY_VA declared: {report.high_entropy_va_declared}")
        print(f"Relocations marked stripped: {report.relocations_stripped}")
        for note in report.review_notes:
            print(f"Review: {note}")
    return 0
