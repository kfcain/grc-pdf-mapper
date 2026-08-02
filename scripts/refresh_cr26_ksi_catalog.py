#!/usr/bin/env python3
"""Refresh lab/fedramp/cr26_ksi_catalog.json from FedRAMP/rules CR26 JSON."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import httpx

from grc_pdf_mapper.fedramp.extract import extract_catalog

UPSTREAM = "https://raw.githubusercontent.com/FedRAMP/rules/main/fedramp-consolidated-rules.json"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--out",
        type=Path,
        default=Path("lab/fedramp/cr26_ksi_catalog.json"),
    )
    parser.add_argument("--from-file", type=Path, help="Use a local CR26 JSON instead of download")
    args = parser.parse_args()

    if args.from_file:
        raw = json.loads(args.from_file.read_text(encoding="utf-8"))
    else:
        with httpx.Client(timeout=60.0, follow_redirects=True) as client:
            resp = client.get(UPSTREAM)
            resp.raise_for_status()
            raw = resp.json()

    catalog = extract_catalog(raw)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(catalog, indent=2), encoding="utf-8")
    n = sum(len(d["indicators"]) for d in catalog["domains"].values())
    print(f"Wrote {args.out} ({n} KSIs, version {catalog['source'].get('version')})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
