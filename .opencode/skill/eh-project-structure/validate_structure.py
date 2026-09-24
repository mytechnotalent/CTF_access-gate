#!/usr/bin/env python3
"""Validate that every EH project's I/R/S documents share one exact structure.

Canonical skeleton (all four projects must be identical):

  <PREFIX>-I.md
    H1  "<Project Title> - Student Instructions"
    H2  Project Overview
    H2  Scenario Briefing
    H2  Learning Objectives
    H2  What This Project Tests
    H2  Part 1: Understanding the System
    H2  Part 2: The Firmware
    H2  Part 3: Your Assignment
    H3  Task 1: ... Task N: ...            (sequential, no gaps)
    H2  How To Breadboard
    H2  Memory Map Reference
    H2  Submission Format
    H2  Success Criteria
    H2  Academic Integrity
    H2  Reference Material

  <PREFIX>-R.md
    H1  "<Project Title> - Requirements & Grading Criteria"
    H2  Project Overview
    H2  Learning Objectives
    H2  Deliverables Checklist
    H2  Required Tools and Equipment
    H2  Artifact Identity
    H2  Grading Rubric - Detailed Breakdown
    H3  Task 1: ... Task N: ...            (sequential, each "(N points)")
    H2  Common Pitfalls
    H2  How To Breadboard
    H2  Memory Map Reference
    H2  Deadline & Submission
    H2  Grade Scale
    H2  Academic Integrity
    H2  Reference Material

  <PREFIX>-S.md
    H1  "<Project Title> - Instructor Solution Key"
    H2  Artifact Identity
    H2  Task 1: ... Task N: ...            (sequential, each "(N points)")
        H3  Solution
        H3  Grading Rubric (1-to-1 Mapping)
        H3  Instructor Notes & Assembly
    H2  How To Breadboard
    H2  Complete Grading Summary
    H2  Instructor Notes
        H3  Common Student Mistakes
        H3  Partial Credit Guidelines
    H2  Appendix: Expected Binary Diff

Also rejected everywhere: em dash (U+2014) and en dash (U+2013).
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3] / "projects"

DASHES = ("\u2013", "\u2014")

I_H2 = [
    "Project Overview",
    "Scenario Briefing",
    "Learning Objectives",
    "What This Project Tests",
    "Part 1: Understanding the System",
    "Part 2: The Firmware",
    "Part 3: Your Assignment",
    "How To Breadboard",
    "Memory Map Reference",
    "Submission Format",
    "Success Criteria",
    "Academic Integrity",
    "Reference Material",
]

R_H2 = [
    "Project Overview",
    "Learning Objectives",
    "Deliverables Checklist",
    "Required Tools and Equipment",
    "Artifact Identity",
    "Grading Rubric - Detailed Breakdown",
    "Common Pitfalls",
    "How To Breadboard",
    "Memory Map Reference",
    "Deadline & Submission",
    "Grade Scale",
    "Academic Integrity",
    "Reference Material",
]

S_TAIL_H2 = [
    "How To Breadboard",
    "Complete Grading Summary",
    "Instructor Notes",
    "Appendix: Expected Binary Diff",
]

S_TASK_H3 = [
    "Solution",
    "Grading Rubric (1-to-1 Mapping)",
    "Instructor Notes & Assembly",
]

SUFFIX = {
    "I": " - Student Instructions",
    "R": " - Requirements & Grading Criteria",
    "S": " - Instructor Solution Key",
}

TASK_RE = re.compile(r"^Task (\d+): .+$")
TASK_PTS_RE = re.compile(r"^Task (\d+): .+ \(\d+ points?\)$")


def headings(text: str):
    h1, h2, h3 = None, [], []
    for line in text.splitlines():
        if line.startswith("### "):
            h3.append(line[4:].strip())
        elif line.startswith("## "):
            h2.append(line[3:].strip())
        elif line.startswith("# ") and h1 is None:
            h1 = line[2:].strip()
    return h1, h2, h3


def check_tasks(items, pattern, where, errors):
    nums = []
    for it in items:
        m = pattern.match(it)
        if not m:
            errors.append(f"{where}: task heading not canonical: {it!r}")
            continue
        nums.append(int(m.group(1)))
    if nums != list(range(1, len(nums) + 1)):
        errors.append(f"{where}: task numbers not sequential 1..N: {nums}")


def check_dashes(text, name, errors):
    for ch in DASHES:
        if ch in text:
            n = text.count(ch)
            errors.append(f"{name}: contains {n} forbidden dash char U+{ord(ch):04X}")


CRIT_RE = re.compile(r"\| (\*\*\[[^]]*\]\*\* .+?|Criterion [0-9.]+: .+?) \| (\d+) \|")


def criterion_rows(path: Path):
    rows = []
    for line in path.read_text().splitlines():
        m = CRIT_RE.match(line)
        if m:
            rows.append((m.group(1).strip(), int(m.group(2))))
    return rows


def check_parity_and_totals(proj: Path, prefix: str, errors: list[str]):
    rpath = proj / f"{prefix}-R.md"
    spath = proj / f"{prefix}-S.md"
    if not (rpath.exists() and spath.exists()):
        return
    r, s = criterion_rows(rpath), criterion_rows(spath)
    rl, sl = [x[0] for x in r], [x[0] for x in s]
    if rl != sl:
        errors.append(f"{prefix}: R/S criterion labels are not 1-to-1")
    if sum(x[1] for x in r) != 100:
        errors.append(f"{prefix}: R rubric points must total 100, got {sum(x[1] for x in r)}")
    if sum(x[1] for x in s) != 100:
        errors.append(f"{prefix}: S rubric points must total 100, got {sum(x[1] for x in s)}")


HASH_RE = re.compile(r"\b([0-9A-Fa-f]{64})\b")


def check_artifact_hashes(proj: Path, prefix: str, errors: list[str]):
    import hashlib

    for kind in ("R", "S"):
        path = proj / f"{prefix}-{kind}.md"
        if not path.exists():
            continue
        text = path.read_text()
        found = {h.upper() for h in HASH_RE.findall(text)}
        for art in (f"{prefix}.bin", f"{prefix}.uf2"):
            f = proj / art
            if not f.exists():
                continue
            digest = hashlib.sha256(f.read_bytes()).hexdigest().upper()
            if digest not in found:
                errors.append(f"{prefix}-{kind}.md: Artifact Identity must list {art} sha256 {digest}")


def validate_project(proj: Path, errors: list[str]):
    candidates = list(proj.glob("*-I.md"))
    if not candidates:
        errors.append(f"{proj.name}: no *-I.md found")
        return
    prefix = candidates[0].stem[:-2]
    for kind in ("I", "R", "S"):
        path = proj / f"{prefix}-{kind}.md"
        if not path.exists():
            errors.append(f"{path.name}: missing")
            continue
        text = path.read_text()
        check_dashes(text, path.name, errors)
        h1, h2, h3 = headings(text)
        if h1 is None:
            errors.append(f"{path.name}: missing H1")
        elif not h1.endswith(SUFFIX[kind]):
            errors.append(
                f"{path.name}: H1 must end with {SUFFIX[kind]!r}, got {h1!r}"
            )

        if kind == "I":
            if h2 != I_H2:
                errors.append(f"{path.name}: H2 skeleton mismatch\n    got: {h2}\n    want:{I_H2}")
        elif kind == "R":
            if h2 != R_H2:
                errors.append(f"{path.name}: H2 skeleton mismatch\n    got: {h2}\n    want:{R_H2}")
        else:
            if not h2 or h2[0] != "Artifact Identity":
                errors.append(f"{path.name}: first H2 must be 'Artifact Identity'")
            tail = h2[-4:] if len(h2) >= 4 else []
            if tail != S_TAIL_H2:
                errors.append(
                    f"{path.name}: S tail must be {S_TAIL_H2}, got {tail}"
                )
            if tail == S_TAIL_H2:
                task_h2 = h2[1:-4]
                check_tasks(task_h2, TASK_PTS_RE, path.name, errors)
                # every task section must contain exactly the three canonical H3s
                for i, t in enumerate(task_h2):
                    start = text.index(f"## {t}") + len(f"## {t}")
                    nxt = (
                        text.index(f"## {task_h2[i + 1]}")
                        if i + 1 < len(task_h2)
                        else text.index(f"## {S_TAIL_H2[0]}")
                    )
                    body = text[start:nxt]
                    subs = [ln[4:].strip() for ln in body.splitlines() if ln.startswith("### ")]
                    if subs != S_TASK_H3:
                        errors.append(f"{path.name}: task {t!r} H3s must be {S_TASK_H3}, got {subs}")

        # Task validation for I and R
        if kind == "I":
            tasks = []
            grab = False
            for line in text.splitlines():
                if line.startswith("## "):
                    grab = line[3:].strip() == "Part 3: Your Assignment"
                elif grab and line.startswith("### "):
                    tasks.append(line[4:].strip())
            check_tasks(tasks, TASK_RE, path.name, errors)
        if kind == "R":
            tasks = []
            grab = False
            for line in text.splitlines():
                if line.startswith("## "):
                    grab = line[3:].strip() == "Grading Rubric - Detailed Breakdown"
                elif grab and line.startswith("### "):
                    tasks.append(line[4:].strip())
            check_tasks(tasks, TASK_PTS_RE, path.name, errors)

    check_parity_and_totals(proj, prefix, errors)
    check_artifact_hashes(proj, prefix, errors)


def _project_dirs(roots):
    found = []
    for root in roots:
        root = Path(root)
        if not root.is_dir():
            continue
        if list(root.glob("*-I.md")):
            found.append(root)
            continue
        found.extend(sorted(p for p in root.iterdir() if p.is_dir()))
    return found


def main() -> int:
    roots = [Path(a) for a in sys.argv[1:]] or [ROOT]
    projects = _project_dirs(roots)
    if not projects:
        print(f"no projects found under {roots}")
        return 1
    errors: list[str] = []
    for proj in projects:
        validate_project(proj, errors)
    if errors:
        print(f"STRUCTURE VALIDATION FAILED ({len(errors)} problem(s)):\n")
        for e in errors:
            print(f"  - {e}")
        return 1
    print(f"STRUCTURE OK: {len(projects)} projects, all I/R/S on one canonical skeleton")
    return 0


if __name__ == "__main__":
    sys.exit(main())
