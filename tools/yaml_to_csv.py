#!/usr/bin/env python3
"""Export a threats.yaml register to the CSV layout in README Appendix C.

Usage:
  python3 tools/yaml_to_csv.py examples/orbitpay/threats.yaml > threat-register.csv
"""
from __future__ import annotations

import csv
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from validate_threats import load  # noqa: E402

COLUMNS = [
    "ID", "Title", "Elements", "STRIDE", "Actor", "Description", "Existing Controls",
    "Likelihood", "Impact", "Risk", "Band", "Response", "Mitigations", "Verification",
    "Ticket", "Owner", "Status", "CWE", "CAPEC", "ATTACK", "Last Reviewed",
]


def rows(data: dict):
    default_review = (data.get("model") or {}).get("last_reviewed", "")
    for t in data.get("threats") or []:
        mits = t.get("mitigations") or []
        refs = t.get("references") or {}
        yield {
            "ID": t["id"],
            "Title": t.get("title", ""),
            "Elements": ";".join(t.get("elements") or []),
            "STRIDE": ";".join(t.get("stride") or []),
            "Actor": t.get("actor", ""),
            "Description": t.get("description", ""),
            "Existing Controls": "; ".join(t.get("existing_controls") or []),
            "Likelihood": t.get("likelihood", ""),
            "Impact": t.get("impact", ""),
            "Risk": t.get("risk", ""),
            "Band": t.get("band", ""),
            "Response": str(t.get("response", "")).capitalize(),
            "Mitigations": "; ".join(f"{m['id']}: {m['description']}" for m in mits),
            "Verification": "; ".join(f"{m['id']}: {m['verification']}" for m in mits),
            "Ticket": ";".join(m["ticket"] for m in mits if m.get("ticket")),
            "Owner": t.get("owner", ""),
            "Status": t.get("status", ""),
            "CWE": ";".join(refs.get("cwe") or []),
            "CAPEC": ";".join(refs.get("capec") or []),
            "ATTACK": ";".join(refs.get("attack") or []),
            "Last Reviewed": t.get("last_reviewed", default_review),
        }


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__, file=sys.stderr)
        return 2
    data = load(Path(argv[1]))
    writer = csv.DictWriter(sys.stdout, fieldnames=COLUMNS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows(data))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
