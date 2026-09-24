---
name: eh-project-structure
description: Use ONLY when creating, editing, or reviewing the Embedded Hacking project documents under EH/projects (the CTF-01, CTF-02, FINAL-01, FINAL-02 folders and their -I.md, -R.md, -S.md files or PDFs). Enforces one canonical section skeleton across all four projects, exact R-to-S criterion parity, 100-point rubrics, artifact hashes, and a ban on em/en dashes.
---

# EH project document standard

Every project under `EH/projects/` is one of four peer projects
(`0x0001b_ctf` = CTF-01, `0x0017a_ctf` = CTF-02, `FINAL-01`, `FINAL-02`).
Each project has exactly the same layout and the same document skeletons.
There is no variation: if one project's document has a section, every peer's
same document has that section, in the same order, with the same heading text.

## Per-project layout

```
<PREFIX>-I.md / .pdf    student instructions
<PREFIX>-R.md / .pdf    requirements and grading criteria
<PREFIX>-S.md / .pdf    instructor solution key
<PREFIX>.bin / .uf2     student artifact
<PREFIX>_fixed.bin/.uf2 solution artifact
<PREFIX>-main-disasm.txt annotated disassembly (FINAL projects; optional for CTFs)
CMakeLists.txt  pico_sdk_import.cmake  uf2conv.py  uf2families.json
src/  include/  scripts/verify_ctf.py  ghidra/
```

`<PREFIX>` is `CTF-01`, `CTF-02`, `FINAL-01`, or `FINAL-02`. Student answer
files are named `<PREFIX>-Answers.md`; the instructor key is `<PREFIX>-S.md`.

## Rule 1: one canonical skeleton per document type

`<PREFIX>-I.md`:

```
# <Project Title> - Student Instructions
## Project Overview
## Scenario Briefing
## Learning Objectives
## What This Project Tests
## Part 1: Understanding the System
## Part 2: The Firmware
## Part 3: Your Assignment
### Task 1: ...
### Task 2: ...
...                    (sequential, no gaps, one per assignment task)
## How To Breadboard
## Memory Map Reference
## Submission Format
## Success Criteria
## Academic Integrity
## Reference Material
```

`<PREFIX>-R.md`:

```
# <Project Title> - Requirements & Grading Criteria
## Project Overview
## Learning Objectives
## Deliverables Checklist
## Required Tools and Equipment
## Artifact Identity
## Grading Rubric - Detailed Breakdown
### Task 1: ... (N points)
### Task 2: ... (N points)
...                    (sequential)
## Common Pitfalls
## How To Breadboard
## Memory Map Reference
## Deadline & Submission
## Grade Scale
## Academic Integrity
## Reference Material
```

`<PREFIX>-S.md`:

```
# <Project Title> - Instructor Solution Key
## Artifact Identity
## Task 1: ... (N points)
### Solution
### Grading Rubric (1-to-1 Mapping)
### Instructor Notes & Assembly
## Task 2: ... (N points)
### Solution
### Grading Rubric (1-to-1 Mapping)
### Instructor Notes & Assembly
...                    (sequential; every task has all three H3s)
## How To Breadboard
## Complete Grading Summary
## Instructor Notes
### Common Student Mistakes
### Partial Credit Guidelines
## Appendix: Expected Binary Diff
```

Project titles: `Operation Black Start`, `Operation Copperhead`,
`The InfuSafe Pro Incident`, `Operation Dark Eclipse`.

Written-analysis questions are not separate sections. They are renumbered as
continuation tasks inside the single task sequence (FINAL-01 tasks 7-9 are
AAPCS, the AI defense, and the SDL; FINAL-02 tasks 6-8 are STUXNET, ethics,
and defensive measures).

## Rule 2: R and S are 1-to-1

For every task, the criterion-label text in `<PREFIX>-R.md` and
`<PREFIX>-S.md` must be identical, row for row. Use the label prefixes already
in use: `**[DOCUMENT]**`, `**[DOCUMENT & PATCH]**`, `**[PATCH]**`, or
`Criterion X.Y:`. Each project's rubric points must total exactly 100, and the
R and S totals must match.

## Rule 3: no em dashes or en dashes

Never write U+2013 (en dash) or U+2014 (em dash) anywhere in these files. Use
the hyphen-minus `-`. This applies to prose, tables, and code comments.

## Rule 4: artifact identity

`<PREFIX>-R.md` and `<PREFIX>-S.md` both contain an `## Artifact Identity`
section with a fenced `text` block listing the uppercase SHA-256 of
`<PREFIX>.bin` and `<PREFIX>.uf2`. Hashes must match the files on disk. If a
binary is rebuilt, update the hashes and regenerate the PDFs.

## Rule 5: keep the PDFs in sync

After editing any `.md`, regenerate its PDF:

```bash
cd /Users/kevinthomas/Documents/data-science/EH
export PUPPETEER_EXECUTABLE_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"
node render-lesson-pdf.mjs projects/<PREFIX>/<PREFIX>-I.md projects/<PREFIX>/<PREFIX>-I.pdf
# repeat for -R and -S
```

## Validate

Run the validator after any change. It fails on any deviation.

```bash
# the four EH projects under projects/
python3 .opencode/skill/eh-project-structure/validate_structure.py

# add any standalone repo that follows the same skeleton (a fifth, sixth, ...),
# for example the OPERATION COLD IRON CTF repo
python3 .opencode/skill/eh-project-structure/validate_structure.py \
  /Users/kevinthomas/Documents/data-science/EH/projects \
  /Users/kevinthomas/Documents/rp2350/11_operation-cold-iron-ctf-c-rp2350
```

Each argument is either a projects root (scanned for subdirectories that contain
a `*-I.md`) or a single project directory that contains `*-I.md` at its top level
(as the standalone CTF repo does). With no arguments it defaults to the four
projects under `projects/`.

Expected output with both roots: `STRUCTURE OK: 5 projects, all I/R/S on one
canonical skeleton`.

For the cross-document checks that the validator does not cover (R/S criterion
parity, 100-point totals, and the dash ban), run the audit described in
Rule 2 and Rule 3, or extend `validate_structure.py` if a new invariant is
added. Any new project added under `projects/` is checked automatically as
long as it follows the layout above.
