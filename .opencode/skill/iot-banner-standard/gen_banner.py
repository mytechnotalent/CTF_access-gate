#!/usr/bin/env python3
"""Render a cool hacker-style repository banner from a banner.json spec.

Produces a 2400x2400 dark terminal-style PNG with a vignette, a glowing accent
title, a framed icon panel, a terminal block, data chips, and a dotted footer.
Every project supplies its own banner.json so the artwork is unique while the
theme stays the same. Run from the repository root; exit zero on success.
"""
import json
import math
import sys
from pathlib import Path

from PIL import Image
from PIL import ImageChops
from PIL import ImageDraw
from PIL import ImageFilter
from PIL import ImageFont

SIZE = 2400
FONT_PATH = "/System/Library/Fonts/Menlo.ttc"
FONT_BOLD = 1
FONT_REGULAR = 0


def _font(size: int, bold: bool) -> ImageFont.FreeTypeFont:
    """
    Load a Menlo face at the requested pixel size.

    Parameters
    ----------
    size : int
        The pixel size.
    bold : bool
        True for the bold face.

    Returns
    -------
    PIL.ImageFont.FreeTypeFont
        The loaded font.
    """
    index = FONT_BOLD if bold else FONT_REGULAR
    return ImageFont.truetype(FONT_PATH, size, index=index)


def _rgb(value: str) -> tuple[int, int, int]:
    """
    Convert a hex color string to an RGB tuple.

    Parameters
    ----------
    value : str
        A hex color such as '#39FF88'.

    Returns
    -------
    tuple[int, int, int]
        The RGB components.
    """
    text = value.lstrip("#")
    return tuple(int(text[i:i + 2], 16) for i in (0, 2, 4))


def _spaced_width(draw: ImageDraw.ImageDraw, text: str,
                  font: ImageFont.FreeTypeFont, tracking: int) -> float:
    """
    Measure the width of letter-spaced text.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    text : str
        The text to measure.
    font : PIL.ImageFont.FreeTypeFont
        The glyph font.
    tracking : int
        Extra pixels between glyphs.

    Returns
    -------
    float
        The total rendered width.
    """
    widths = [draw.textlength(ch, font=font) for ch in text]
    return sum(widths) + tracking * max(0, len(text) - 1)


def _spaced_text(draw: ImageDraw.ImageDraw, x: float, y: float, text: str,
                 font: ImageFont.FreeTypeFont, fill, tracking: int) -> float:
    """
    Draw letter-spaced text and return the end x position.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    x : float
        The starting x position.
    y : float
        The baseline top position.
    text : str
        The text to draw.
    font : PIL.ImageFont.FreeTypeFont
        The glyph font.
    fill : tuple
        The glyph color.
    tracking : int
        Extra pixels between glyphs.

    Returns
    -------
    float
        The x position after the last glyph.
    """
    cursor = x
    for ch in text:
        draw.text((cursor, y), ch, font=font, fill=fill)
        cursor += draw.textlength(ch, font=font) + tracking
    return cursor


def _centered(draw: ImageDraw.ImageDraw, y: int, text: str,
              font: ImageFont.FreeTypeFont, fill, tracking: int) -> None:
    """
    Draw letter-spaced text centered on the canvas.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    y : int
        The baseline top position.
    text : str
        The text to draw.
    font : PIL.ImageFont.FreeTypeFont
        The glyph font.
    fill : tuple
        The glyph color.
    tracking : int
        Extra pixels between glyphs.

    Returns
    -------
    None
    """
    width = _spaced_width(draw, text, font, tracking)
    _spaced_text(draw, (SIZE - width) / 2, y, text, font, fill, tracking)


def _background(spec: dict) -> Image.Image:
    """
    Build the vignetted dark background.

    Parameters
    ----------
    spec : dict
        The banner specification.

    Returns
    -------
    PIL.Image.Image
        The RGB background image.
    """
    base = Image.new("RGB", (SIZE, SIZE), _rgb(spec["bg"]))
    mask = _vignette_mask()
    dark = Image.new("RGB", (SIZE, SIZE), _rgb(spec.get("bg_edge", "#000000")))
    return Image.composite(base, dark, mask)


def _vignette_mask() -> Image.Image:
    """
    Build a radial vignette mask.

    Parameters
    ----------
    None

    Returns
    -------
    PIL.Image.Image
        The single-channel vignette mask.
    """
    small = Image.new("L", (64, 64), 0)
    pixels = small.load()
    for y in range(64):
        for x in range(64):
            dist = (((x - 31.5) ** 2 + (y - 31.5) ** 2) ** 0.5) / 42.0
            pixels[x, y] = int(max(0.0, min(1.0, 1.0 - dist)) * 255)
    return small.resize((SIZE, SIZE), Image.BICUBIC)


def _screen_glow(base: Image.Image, layer: Image.Image,
                 radius: float) -> Image.Image:
    """
    Add a blurred glow layer onto the base with a screen blend.

    Parameters
    ----------
    base : PIL.Image.Image
        The RGB base image.
    layer : PIL.Image.Image
        The RGB glow layer on black.
    radius : float
        The blur radius.

    Returns
    -------
    PIL.Image.Image
        The composited RGB image.
    """
    blurred = layer.filter(ImageFilter.GaussianBlur(radius))
    return ImageChops.screen(base, blurred)


def _glow_layer() -> Image.Image:
    """
    Create a black RGB layer used for glow rendering.

    Parameters
    ----------
    None

    Returns
    -------
    PIL.Image.Image
        A black RGB image.
    """
    return Image.new("RGB", (SIZE, SIZE), (0, 0, 0))


def _rounded(draw: ImageDraw.ImageDraw, box: tuple, radius: int,
             fill, outline, width: int) -> None:
    """
    Draw a rounded rectangle panel.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    box : tuple
        The (x0, y0, x1, y1) bounds.
    radius : int
        The corner radius.
    fill : tuple
        The interior color.
    outline : tuple
        The border color.
    width : int
        The border width.

    Returns
    -------
    None
    """
    draw.rounded_rectangle(box, radius=radius, fill=fill, outline=outline,
                           width=width)


def _leaf(draw: ImageDraw.ImageDraw, cx: int, cy: int, accent) -> None:
    """
    Draw a pointed leaf glyph with a midrib and veins.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    cx : int
        The leaf center x.
    cy : int
        The leaf center y.
    accent : tuple
        The leaf color.

    Returns
    -------
    None
    """
    half_w, half_h = 170, 120
    top = [(cx - half_w + 2 * half_w * (i / 40),
            cy - half_h * math.sin(math.pi * i / 40)) for i in range(41)]
    bottom = [(cx + half_w - 2 * half_w * (i / 40),
               cy + half_h * math.sin(math.pi * i / 40)) for i in range(41)]
    draw.line(top + bottom + [top[0]], fill=accent, width=14, joint="curve")
    draw.line((cx - half_w, cy, cx + half_w, cy), fill=accent, width=12)
    _veins(draw, cx, cy, half_w, accent)


def _veins(draw: ImageDraw.ImageDraw, cx: int, cy: int, half_w: int,
           accent) -> None:
    """
    Draw the leaf side veins.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    cx : int
        The leaf center x.
    cy : int
        The leaf center y.
    half_w : int
        The leaf half width.
    accent : tuple
        The vein color.

    Returns
    -------
    None
    """
    for step in (0.3, 0.5, 0.7):
        base = cx - half_w + 2 * half_w * step
        draw.line((base, cy, base - 55, cy - 60), fill=accent, width=8)
        draw.line((base, cy, base - 55, cy + 60), fill=accent, width=8)


def _icon(draw: ImageDraw.ImageDraw, cx: int, cy: int, kind: str,
          accent, dim) -> None:
    """
    Draw the central project icon.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    cx : int
        The icon center x.
    cy : int
        The icon center y.
    kind : str
        The icon kind: thermo, leaf, or drop.
    accent : tuple
        The accent color.
    dim : tuple
        The dim accent color.

    Returns
    -------
    None
    """
    if kind == "leaf":
        _leaf(draw, cx, cy, accent)
    elif kind == "drop":
        draw.ellipse((cx - 95, cy - 20, cx + 95, cy + 130), outline=accent,
                     width=14)
        draw.polygon((cx, cy - 130, cx - 95, cy + 30, cx + 95, cy + 30),
                     outline=accent, width=14)
    else:
        draw.rounded_rectangle((cx - 30, cy - 130, cx + 30, cy + 25), radius=30,
                               outline=accent, width=14)
        draw.ellipse((cx - 62, cy + 10, cx + 62, cy + 130), outline=accent,
                     width=14)
        draw.ellipse((cx - 30, cy + 42, cx + 30, cy + 98), fill=dim)


def _chip(draw: ImageDraw.ImageDraw, x: int, y: int, w: int, h: int,
          label: str, value: str, accent, dim) -> None:
    """
    Draw one data chip.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    x : int
        The chip left edge.
    y : int
        The chip top edge.
    w : int
        The chip width.
    h : int
        The chip height.
    label : str
        The chip label.
    value : str
        The chip value.
    accent : tuple
        The accent color.
    dim : tuple
        The dim text color.

    Returns
    -------
    None
    """
    _rounded(draw, (x, y, x + w, y + h), 18, (0x0C, 0x10, 0x14), dim, 3)
    draw.text((x + 24, y + 18), label, font=_font(34, True), fill=accent)
    draw.text((x + 24, y + 66), value, font=_font(34, False), fill=dim)


def _terminal(draw: ImageDraw.ImageDraw, box: tuple, lines: list,
              accent, dim, cyan) -> None:
    """
    Draw the terminal transcript block.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    box : tuple
        The (x0, y0, x1, y1) bounds.
    lines : list
        The transcript lines.
    accent : tuple
        The accent color.
    dim : tuple
        The dim text color.
    cyan : tuple
        The secondary color.

    Returns
    -------
    None
    """
    _rounded(draw, box, 24, (0x08, 0x0B, 0x0E), dim, 3)
    font = _font(40, False)
    y = box[1] + 40
    for line in lines:
        color = dim
        if line.startswith("[*]"):
            color = cyan
        elif line.startswith("[+]"):
            color = accent
        draw.text((box[0] + 40, y), line, font=font, fill=color)
        y += 64


def _cards(draw: ImageDraw.ImageDraw, y: int, cards: list, accent,
           dim, white) -> None:
    """
    Draw the row of status cards.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    y : int
        The card top edge.
    cards : list
        Card dictionaries with tag, label, and value.
    accent : tuple
        The accent color.
    dim : tuple
        The dim text color.
    white : tuple
        The bright text color.

    Returns
    -------
    None
    """
    gap, margin = 40, 120
    width = (SIZE - 2 * margin - gap * (len(cards) - 1)) // len(cards)
    for index, card in enumerate(cards):
        x = margin + index * (width + gap)
        _rounded(draw, (x, y, x + width, y + 170), 20, (0x0C, 0x10, 0x14),
                 dim, 3)
        draw.text((x + 30, y + 26), card["tag"], font=_font(38, True),
                  fill=accent)
        draw.text((x + 30, y + 80), card["label"], font=_font(34, False),
                  fill=white)
        draw.text((x + 30, y + 122), card["value"], font=_font(34, True),
                  fill=dim)


def _dots(draw: ImageDraw.ImageDraw, y: int, count: int, color) -> None:
    """
    Draw a row of separator dots.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    y : int
        The dot center row.
    count : int
        The number of dots.
    color : tuple
        The dot color.

    Returns
    -------
    None
    """
    margin = 160
    step = (SIZE - 2 * margin) / (count - 1)
    for index in range(count):
        x = margin + index * step
        draw.ellipse((x - 5, y - 5, x + 5, y + 5), fill=color)


def _render(spec: dict) -> Image.Image:
    """
    Render the full banner image.

    Parameters
    ----------
    spec : dict
        The banner specification.

    Returns
    -------
    PIL.Image.Image
        The rendered RGB banner.
    """
    accent = _rgb(spec["accent"])
    dim = _rgb(spec.get("dim", "#6B7280"))
    white = _rgb(spec.get("white", "#F2F5FF"))
    cyan = _rgb(spec.get("cyan", "#7FD8E0"))
    base = _background(spec)
    glow = _glow_layer()
    _title_texts(ImageDraw.Draw(glow), spec, accent)
    base = _screen_glow(base, glow, 26)
    draw = ImageDraw.Draw(base)
    _title_texts(draw, spec, accent)
    _panel(draw, spec, accent, dim, white)
    _terminal(draw, (120, 1290, 2280, 1660), spec["terminal"], accent, dim,
              cyan)
    _centered(draw, 1730, "   ".join(spec["categories"]), _font(56, True),
              white, 24)
    _cards(draw, 1850, spec["cards"], accent, dim, white)
    _footer(draw, spec, accent, dim, white)
    return base


def _title_texts(draw: ImageDraw.ImageDraw, spec: dict, accent) -> None:
    """
    Draw the eyebrow, title, and subtitle lines.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    spec : dict
        The banner specification.
    accent : tuple
        The accent color.

    Returns
    -------
    None
    """
    _centered(draw, 120, spec["eyebrow"], _font(44, True), accent, 16)
    _centered(draw, 230, spec["title"], _font(190, True),
              (0xF2, 0xF5, 0xFF), 10)
    _centered(draw, 500, spec["subtitle"], _font(58, True), accent, 22)


def _panel(draw: ImageDraw.ImageDraw, spec: dict, accent, dim,
           white) -> None:
    """
    Draw the framed icon panel with its status line and chips.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    spec : dict
        The banner specification.
    accent : tuple
        The accent color.
    dim : tuple
        The dim text color.
    white : tuple
        The bright text color.

    Returns
    -------
    None
    """
    _rounded(draw, (120, 620, 2280, 1230), 40, (0x09, 0x0D, 0x10), accent, 4)
    _icon(draw, SIZE // 2, 790, spec["icon"], accent, _rgb(spec["bg"]))
    _centered(draw, 990, spec["panel_status"], _font(50, True), accent, 12)
    chips = spec["chips"]
    gap, margin = 30, 170
    width = (SIZE - 2 * margin - gap * (len(chips) - 1)) // len(chips)
    for index, chip in enumerate(chips):
        x = margin + index * (width + gap)
        _chip(draw, x, 1060, width, 130, chip["label"], chip["value"], accent,
              white)


def _footer(draw: ImageDraw.ImageDraw, spec: dict, accent, dim,
            white) -> None:
    """
    Draw the dotted footer lines.

    Parameters
    ----------
    draw : PIL.ImageDraw.ImageDraw
        The drawing surface.
    spec : dict
        The banner specification.
    accent : tuple
        The accent color.
    dim : tuple
        The dim text color.
    white : tuple
        The bright text color.

    Returns
    -------
    None
    """
    _dots(draw, 2080, 40, dim)
    _centered(draw, 2150, spec["footer"][0], _font(44, True), accent, 14)
    _centered(draw, 2240, spec["footer"][1], _font(40, True), white, 12)
    _dots(draw, 2330, 40, dim)


def main() -> int:
    """
    Load the spec, render the banner, and write the PNG artifact.

    Parameters
    ----------
    None

    Returns
    -------
    int
        Zero on success.
    """
    root = Path.cwd()
    spec = json.loads((root / "banner.json").read_text(encoding="utf-8"))
    out = root / f"{spec['repo']}.png"
    _render(spec).save(out)
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
