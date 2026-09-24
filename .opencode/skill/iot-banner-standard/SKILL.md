---
name: iot-banner-standard
description: Use ONLY when creating or reviewing the repository banner (the <repo>.png logo referenced at the top of the README) of an iot-NNNNN project. Enforces the fixed dark terminal-style hacker theme rendered from banner.json by gen_banner.py at 2400x2400, unique per project by accent color, icon, and copy, and referenced by the exact raw GitHub URL. No exceptions and no variation in theme between projects.
---

# IoT banner standard (iot-NNNNN)

Every project ships a `<repo>.png` banner at the repository root and references
it from the first line of the README. The artwork is generated, never hand
drawn, so the theme is identical across the series while the content is unique.

## The fixed theme

Every banner is a 2400x2400 dark terminal poster with these layers, top to
bottom:

1. A dark tinted background with a radial vignette.
2. An eyebrow line: `PROJECT <N> // RASPBERRY PI PICO 2`.
3. A huge letter-spaced glowing title: `IOT // <DOMAIN>`.
4. A letter-spaced accent subtitle.
5. A framed rounded panel with a glowing project icon, a status line, and four
   data chips.
6. A terminal transcript block with `$`, `[*]`, and `[+]` lines.
7. A row of four category labels.
8. A row of three status cards.
9. Two dotted footer lines.

Only these change between projects: the accent color, the icon kind, the title
and subtitle, the status line, the chips, the transcript, the categories, the
cards, and the footer text. The layout, fonts, and layers never change.

## The spec

`banner.json` at the repository root drives the render. Required keys:
`repo`, `eyebrow`, `title`, `subtitle`, `accent`, `bg`, `icon`, `panel_status`,
`chips`, `terminal`, `categories`, `cards`, `footer`. Optional keys: `dim`,
`white`, `cyan`, `bg_edge`. The icon kind is one of `thermo`, `leaf`, or
`drop`.

Pick one accent color per project so the series is a rainbow of the same
design. Keep the background a near-black tint of the accent.

## Generate

```bash
python3 .opencode/skill/iot-banner-standard/gen_banner.py
```

This writes `<repo>.png` at the repository root. The README first line must be
exactly:

```
![<repo>](https://raw.githubusercontent.com/mytechnotalent/<repo>/main/<repo>.png)
```

## Verify

```bash
python3 .opencode/skill/iot-banner-standard/validate_banner.py
```

Exit 0 is clean; any output is a failure and must be fixed before the change is
complete.
