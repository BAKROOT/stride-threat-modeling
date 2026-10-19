#!/usr/bin/env python3
"""Validate STRIDE threat registers (threats.yaml) and enforce threat-model policy.

Checks
------
Structural (JSON Schema, templates/threats.schema.json):
  required fields, ID formats, STRIDE letters, 1-5 scales, allowed statuses.

Semantic:
  * unique element, threat and mitigation IDs
  * every threat element reference exists in the element inventory
  * data flows reference existing source/destination elements
  * risk == likelihood x impact, and band matches the calibrated scale
  * threats at or above the blocking threshold (default 12, "High") may not be
    `open`: they need a mitigation in progress or a formal acceptance
  * `accepted` threats need an acceptance block (approver, rationale, expiry)
    whose expiry date has not passed
  * mitigate/eliminate responses need at least one mitigation
  * optional: mitigation `verification_path` files must exist (--check-paths)

Warnings (never fail the build unless --strict):
  * model or threat review older than --max-age-days
  * STRIDE category outside the STRIDE-per-element chart for that element type

Usage
-----
  python3 tools/validate_threats.py examples/orbitpay/threats.yaml
  python3 tools/validate_threats.py $(git ls-files '**/threats.yaml') --coverage

Exit code 0 = pass, 1 = policy or schema errors, 2 = usage / file errors.
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    sys.exit("PyYAML is required: pip install -r tools/requirements.txt")

try:
    import jsonschema
except ImportError:  # pragma: no cover
    jsonschema = None

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_SCHEMA = REPO_ROOT / "templates" / "threats.schema.json"

STRIDE = ["S", "T", "R", "I", "D", "E"]

# STRIDE-per-element chart (README Section 6.1). Repudiation on data stores
# applies only to stores that hold logs / audit records (log_store: true).
APPLICABLE = {
    "external_entity": {"S", "R"},
    "process": set(STRIDE),
    "data_store": {"T", "I", "D"},
    "data_flow": {"T", "I", "D"},
}


def band_for(risk: int) -> str:
    """Calibrated 5x5 bands (README Section 8.2)."""
    if risk >= 20:
        return "Critical"
    if risk >= 12:
        return "High"
    if risk >= 6:
        return "Medium"
    return "Low"


def applicable(element: dict) -> set[str]:
    cats = set(APPLICABLE.get(element.get("type", ""), set()))
    if element.get("type") == "data_store" and element.get("log_store"):
        cats.add("R")
    return cats


@dataclass
class Report:
    path: Path
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def error(self, msg: str) -> None:
        self.errors.append(msg)

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)


def _normalise(obj):
    """YAML turns ISO dates into date objects; the schema expects strings."""
    if isinstance(obj, dict):
        return {k: _normalise(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_normalise(v) for v in obj]
    if isinstance(obj, (dt.date, dt.datetime)):
        return obj.isoformat()[:10]
    return obj


def _parse_date(value, report: Report, where: str) -> dt.date | None:
    try:
        return dt.date.fromisoformat(str(value))
    except ValueError:
        report.error(f"{where}: '{value}' is not an ISO date (YYYY-MM-DD)")
        return None


def load(path: Path) -> dict:
    with path.open(encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError("top level must be a mapping with model, elements and threats")
    return _normalise(data)


def schema_check(data: dict, schema: dict, report: Report) -> None:
    if jsonschema is None:
        report.warn("jsonschema not installed; structural checks skipped")
        return
    validator = jsonschema.Draft202012Validator(schema)
    for err in sorted(validator.iter_errors(data), key=lambda e: list(e.absolute_path)):
        loc = "/".join(str(p) for p in err.absolute_path) or "<root>"
        report.error(f"schema: {loc}: {err.message}")


def semantic_check(data: dict, report: Report, *, today: dt.date, threshold: int,
                   max_age_days: int, check_paths: bool, base_dir: Path) -> None:
    elements = data.get("elements") or []
    threats = data.get("threats") or []
    model = data.get("model") or {}

    # --- element inventory -------------------------------------------------
    by_id: dict[str, dict] = {}
    for el in elements:
        eid = el.get("id")
        if eid in by_id:
            report.error(f"element {eid}: duplicate ID")
        by_id[eid] = el
    for el in elements:
        if el.get("type") == "data_flow":
            for end in ("from", "to"):
                ref = el.get(end)
                if ref is None:
                    report.error(f"element {el.get('id')}: data flow missing '{end}'")
                elif ref not in by_id:
                    report.error(f"element {el.get('id')}: '{end}' references unknown element {ref}")

    for note in data.get("coverage_notes") or []:
        if note.get("element") not in by_id:
            report.error(f"coverage_notes: unknown element {note.get('element')}")

    # --- model freshness ---------------------------------------------------
    if "last_reviewed" in model:
        reviewed = _parse_date(model["last_reviewed"], report, "model.last_reviewed")
        if reviewed and (today - reviewed).days > max_age_days:
            report.warn(f"model last reviewed {reviewed} (> {max_age_days} days ago)")

    # --- threats -----------------------------------------------------------
    seen_threats: set[str] = set()
    seen_mitigations: set[str] = set()
    for t in threats:
        tid = t.get("id", "<no id>")
        if tid in seen_threats:
            report.error(f"{tid}: duplicate threat ID")
        seen_threats.add(tid)

        stride = t.get("stride") or []
        for ref in t.get("elements") or []:
            el = by_id.get(ref)
            if el is None:
                report.error(f"{tid}: references unknown element {ref}")
                continue
        # STRIDE-per-element is a starting point, not a restriction (README 6.1):
        # warn only when no referenced element admits a listed category.
        refs = [by_id[r] for r in (t.get("elements") or []) if r in by_id]
        if refs:
            allowed = set().union(*(applicable(e) for e in refs))
            for cat in stride:
                if cat not in allowed:
                    report.warn(f"{tid}: '{cat}' is outside the STRIDE-per-element chart "
                                f"for {', '.join(e['id'] for e in refs)}; confirm it is intended")

        likelihood, impact, risk = t.get("likelihood"), t.get("impact"), t.get("risk")
        if all(isinstance(v, int) for v in (likelihood, impact, risk)):
            if risk != likelihood * impact:
                report.error(f"{tid}: risk {risk} != likelihood {likelihood} x impact {impact}")
            expected = band_for(likelihood * impact)
            if t.get("band") != expected:
                report.error(f"{tid}: band '{t.get('band')}' should be '{expected}' "
                             f"for risk {likelihood * impact}")

        status, response = t.get("status"), t.get("response")
        mitigations = t.get("mitigations") or []
        for m in mitigations:
            mid = m.get("id")
            if mid in seen_mitigations:
                report.error(f"{tid}: duplicate mitigation ID {mid}")
            seen_mitigations.add(mid)
            if check_paths and m.get("verification_path"):
                vpath = (base_dir / m["verification_path"]).resolve()
                if not vpath.exists():
                    report.error(f"{tid}/{mid}: verification_path not found: {m['verification_path']}")

        if response in ("mitigate", "eliminate") and not mitigations:
            report.error(f"{tid}: response '{response}' but no mitigations listed")

        acceptance = t.get("acceptance")
        if status == "accepted" or response == "accept":
            if not acceptance:
                report.error(f"{tid}: accepted risk needs an acceptance block "
                             "(approved_by, rationale, expires)")
            else:
                expires = _parse_date(acceptance.get("expires"), report, f"{tid}.acceptance.expires")
                if expires and expires < today:
                    report.error(f"{tid}: risk acceptance expired on {expires}; re-review required")

        if isinstance(risk, int) and risk >= threshold and status == "open":
            report.error(f"{tid}: risk {risk} ({t.get('band')}) is 'open'; threats >= {threshold} "
                         "need a mitigation in progress or a time-bound acceptance")

        if "last_reviewed" in t:
            reviewed = _parse_date(t["last_reviewed"], report, f"{tid}.last_reviewed")
            if reviewed and (today - reviewed).days > max_age_days:
                report.warn(f"{tid}: last reviewed {reviewed} (> {max_age_days} days ago)")


def coverage_matrix(data: dict) -> tuple[str, int]:
    """Markdown STRIDE coverage matrix (README Section 6.3) and count of unexamined cells."""
    cells: dict[str, dict[str, list[str]]] = {}
    for t in data.get("threats") or []:
        for ref in t.get("elements") or []:
            for cat in t.get("stride") or []:
                cells.setdefault(ref, {}).setdefault(cat, []).append(t["id"])
    notes: dict[tuple[str, str], str] = {
        (n["element"], n["stride"]): n["note"] for n in data.get("coverage_notes") or []
    }

    gaps = 0
    lines = ["| Element | " + " | ".join(STRIDE) + " |", "|---|" + "---|" * len(STRIDE)]
    for el in data.get("elements") or []:
        row = []
        for cat in STRIDE:
            ids = cells.get(el["id"], {}).get(cat)
            note = notes.get((el["id"], cat))
            if ids:
                row.append(", ".join(ids) + (f" ({note})" if note else ""))
            elif note:
                row.append(note)
            elif cat in applicable(el):
                row.append("**?**")
                gaps += 1
            else:
                row.append("n/a")
        lines.append(f"| {el['id']} {el['name']} | " + " | ".join(row) + " |")
    lines.append("")
    lines.append("`**?**` = applicable per STRIDE-per-element but no threat recorded. "
                 "Record a threat, or write \"None found\" with a reason in the model document.")
    return "\n".join(lines), gaps


def summary(data: dict) -> str:
    counts = {b: 0 for b in ("Critical", "High", "Medium", "Low")}
    for t in data.get("threats") or []:
        if t.get("band") in counts:
            counts[t["band"]] += 1
    return ", ".join(f"{v} {k}" for k, v in counts.items())


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("files", nargs="+", type=Path, help="threats.yaml file(s)")
    ap.add_argument("--schema", type=Path, default=DEFAULT_SCHEMA)
    ap.add_argument("--threshold", type=int, default=12,
                    help="risk score at or above which 'open' threats block (default 12)")
    ap.add_argument("--max-age-days", type=int, default=180)
    ap.add_argument("--today", type=dt.date.fromisoformat, default=dt.date.today(),
                    help="override today's date (YYYY-MM-DD), useful for tests")
    ap.add_argument("--check-paths", action="store_true",
                    help="require mitigation verification_path files to exist")
    ap.add_argument("--coverage", action="store_true", help="print the STRIDE coverage matrix")
    ap.add_argument("--fail-on-gaps", action="store_true",
                    help="fail if the coverage matrix has unexamined applicable cells")
    ap.add_argument("--strict", action="store_true", help="treat warnings as errors")
    args = ap.parse_args(argv)

    try:
        schema = json.loads(args.schema.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        print(f"error: cannot read schema {args.schema}: {exc}", file=sys.stderr)
        return 2

    failed = False
    for path in args.files:
        report = Report(path)
        try:
            data = load(path)
        except (OSError, yaml.YAMLError, ValueError) as exc:
            print(f"✗ {path}: cannot load: {exc}", file=sys.stderr)
            return 2

        schema_check(data, schema, report)
        semantic_check(data, report, today=args.today, threshold=args.threshold,
                       max_age_days=args.max_age_days, check_paths=args.check_paths,
                       base_dir=path.parent)

        gaps = 0
        if args.coverage or args.fail_on_gaps:
            matrix, gaps = coverage_matrix(data)
            if args.coverage:
                print(f"\n### STRIDE coverage: {path}\n\n{matrix}\n")
            if args.fail_on_gaps and gaps:
                report.error(f"coverage matrix has {gaps} unexamined applicable cell(s)")

        for w in report.warnings:
            print(f"  warning: {w}")
        for e in report.errors:
            print(f"  error:   {e}")

        bad = bool(report.errors) or (args.strict and bool(report.warnings))
        failed |= bad
        n = len(data.get("threats") or [])
        mark = "✗" if bad else "✓"
        print(f"{mark} {path}: {n} threats ({summary(data)}); "
              f"{len(report.errors)} error(s), {len(report.warnings)} warning(s)")

    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
