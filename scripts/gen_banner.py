#!/usr/bin/env python3
"""Generate the access-gate.png repository banner (1500x1500, pure stdlib).

MIT License
Copyright (c) 2026 Kevin Thomas
"""
from __future__ import annotations

import struct
import sys
import zlib
from pathlib import Path


def _glyph_lines(ch: str) -> tuple[str, ...]:
    """Return the five-by-seven glyph rows for a character.

    Parameters
    ----------
    ch : str
        The single character whose glyph rows are returned.

    Returns
    -------
    tuple[str, ...]
        Seven strings of five '0'/'1' columns each.
    """
    font = {
        " ": ("00000",) * 7,
        "!": ("00100", "00100", "00100", "00100", "00000", "00100", "00100"),
        "+": ("00000", "00100", "00100", "11111", "00100", "00100", "00000"),
        "-": ("00000", "00000", "00000", "11111", "00000", "00000", "00000"),
        ".": ("00000", "00000", "00000", "00000", "00000", "01100", "01100"),
        ":": ("00000", "01100", "01100", "00000", "01100", "01100", "00000"),
        "'": ("00100", "00100", "00000", "00000", "00000", "00000", "00000"),
        "/": ("00001", "00010", "00010", "00100", "01000", "01000", "10000"),
        "=": ("00000", "00000", "11111", "00000", "11111", "00000", "00000"),
        ">": ("00001", "00001", "00010", "00100", "00010", "00001", "00001"),
        "[": ("01110", "01000", "01000", "01000", "01000", "01000", "01110"),
        "]": ("01110", "00010", "00010", "00010", "00010", "00010", "01110"),
        "%": ("10001", "10011", "00010", "00100", "01000", "11001", "10001"),
        "&": ("01110", "10001", "10010", "01100", "10010", "10001", "01111"),
        "0": ("01110", "10001", "10011", "10101", "11001", "10001", "01110"),
        "1": ("00100", "01100", "00100", "00100", "00100", "00100", "01110"),
        "2": ("01110", "10001", "00001", "00010", "00100", "01000", "11111"),
        "3": ("11111", "00010", "00100", "00010", "00001", "10001", "01110"),
        "4": ("00010", "00110", "01010", "10010", "11111", "00010", "00010"),
        "5": ("11111", "10000", "11110", "00001", "00001", "10001", "01110"),
        "6": ("00110", "01000", "10000", "11110", "10001", "10001", "01110"),
        "7": ("11111", "00001", "00010", "00100", "01000", "01000", "01000"),
        "8": ("01110", "10001", "10001", "01110", "10001", "10001", "01110"),
        "9": ("01110", "10001", "10001", "01111", "00001", "00010", "01100"),
        "A": ("01110", "10001", "10001", "11111", "10001", "10001", "10001"),
        "B": ("11110", "10001", "10001", "11110", "10001", "10001", "11110"),
        "C": ("01111", "10000", "10000", "10000", "10000", "10000", "01111"),
        "D": ("11110", "10001", "10001", "10001", "10001", "10001", "11110"),
        "E": ("11111", "10000", "10000", "11110", "10000", "10000", "11111"),
        "F": ("11111", "10000", "10000", "11110", "10000", "10000", "10000"),
        "G": ("01111", "10000", "10000", "10111", "10001", "10001", "01111"),
        "H": ("10001", "10001", "10001", "11111", "10001", "10001", "10001"),
        "I": ("11111", "00100", "00100", "00100", "00100", "00100", "11111"),
        "J": ("00111", "00010", "00010", "00010", "00010", "10010", "01100"),
        "K": ("10001", "10010", "10100", "11000", "10100", "10010", "10001"),
        "L": ("10000", "10000", "10000", "10000", "10000", "10000", "11111"),
        "M": ("10001", "11011", "10101", "10101", "10001", "10001", "10001"),
        "N": ("10001", "11001", "10101", "10011", "10001", "10001", "10001"),
        "O": ("01110", "10001", "10001", "10001", "10001", "10001", "01110"),
        "P": ("11110", "10001", "10001", "11110", "10000", "10000", "10000"),
        "Q": ("01110", "10001", "10001", "10101", "10010", "10001", "01101"),
        "R": ("11110", "10001", "10001", "11110", "10100", "10010", "10001"),
        "S": ("01111", "10000", "10000", "01110", "00001", "00001", "11110"),
        "T": ("11111", "00100", "00100", "00100", "00100", "00100", "00100"),
        "U": ("10001", "10001", "10001", "10001", "10001", "10001", "01110"),
        "V": ("10001", "10001", "10001", "10001", "10001", "01010", "00100"),
        "W": ("10001", "10001", "10001", "10101", "10101", "11011", "10001"),
        "X": ("10001", "10001", "01010", "00100", "01010", "10001", "10001"),
        "Y": ("10001", "10001", "01010", "00100", "00100", "00100", "00100"),
        "Z": ("11111", "00001", "00010", "00100", "01000", "10000", "11111"),
        "_": ("00000", "00000", "00000", "00000", "00000", "00000", "11111"),
    }
    if len(ch) != 1:
        raise ValueError("glyph key must be a single character")
    return font.get(ch.upper(), font[" "])


def _lerp(a: int, b: int, t: float) -> int:
    """Linearly interpolate one integer component toward another.

    Parameters
    ----------
    a : int
        The lower component.
    b : int
        The upper component.
    t : float
        The interpolation factor in the closed interval [0, 1].

    Returns
    -------
    int
        The interpolated component value.
    """
    return int(a + (b - a) * t)


class Banner:
    """Fifteen-hundred-pixel banner raster canvas.

    Parameters
    ----------
    None

    Returns
    -------
    None
    """

    W = 1500
    H = 1500

    def __init__(self) -> None:
        """Initialize the scanlined navy gradient background.

        Parameters
        ----------
        None

        Returns
        -------
        None
        """
        self.frame: list[list[tuple[int, int, int]]] = []
        for y in range(self.H):
            t = y / self.H
            row = [
                (
                    _lerp(0x0D, 0x05, t),
                    _lerp(0x12, 0x07, t),
                    _lerp(0x28, 0x10, t),
                )
                for _ in range(self.W)
            ]
            if y % 5 == 0:
                row = [
                    (int(px[0] * 0.93), int(px[1] * 0.93), int(px[2] * 0.93))
                    for px in row
                ]
            self.frame.append(row)

    def fill_rect(
        self,
        x: int,
        y: int,
        w: int,
        h: int,
        color: tuple[int, int, int],
    ) -> None:
        """Paint a solid rectangle clipped to the canvas bounds.

        Parameters
        ----------
        x : int
            The left column of the rectangle.
        y : int
            The top row of the rectangle.
        w : int
            The rectangle width in columns.
        h : int
            The rectangle height in rows.
        color : tuple[int, int, int]
            The RGB color to paint.

        Returns
        -------
        None
        """
        for j in range(y, min(y + h, self.H)):
            if j < 0:
                continue
            row = self.frame[j]
            for i in range(max(x, 0), min(x + w, self.W)):
                row[i] = color

    def rect_border(
        self,
        x: int,
        y: int,
        w: int,
        h: int,
        thickness: int,
        color: tuple[int, int, int],
    ) -> None:
        """Paint a rectangular outline by four overlapping bars.

        Parameters
        ----------
        x : int
            The left column of the rectangle.
        y : int
            The top row of the rectangle.
        w : int
            The rectangle width in columns.
        h : int
            The rectangle height in rows.
        thickness : int
            The border thickness in columns.
        color : tuple[int, int, int]
            The RGB color to paint.

        Returns
        -------
        None
        """
        self.fill_rect(x, y, w, thickness, color)
        self.fill_rect(x, y + h - thickness, w, thickness, color)
        self.fill_rect(x, y, thickness, h, color)
        self.fill_rect(x + w - thickness, y, thickness, h, color)

    def text(
        self,
        value: str,
        scale: int,
        color: tuple[int, int, int],
        cx: int,
        top: int,
    ) -> int:
        """Render a line of text centered on a column and return the base.

        Parameters
        ----------
        value : str
            The text to render in upper-case glyphs.
        scale : int
            The integer pixel scale factor per glyph cell.
        color : tuple[int, int, int]
            The RGB glyph color.
        cx : int
            The horizontal center column for the rendered text.
        top : int
            The top row where the glyph cell grid begins.

        Returns
        -------
        int
            The row one past the last rendered pixel cell.
        """
        glyphs = [_glyph_lines(ch) for ch in value.upper()]
        total = sum(5 * scale for _ in glyphs) + 2 * scale * (len(glyphs) - 1)
        x = cx - total // 2
        for glyph in glyphs:
            for row in range(7):
                line = glyph[row]
                for col in range(5):
                    if line[col] == "1":
                        px = x + col * scale
                        py = top + row * scale
                        self.fill_rect(px, py, scale, scale, color)
            x += 7 * scale
        return top + 7 * scale

    def chip(
        self,
        cx: int,
        cy: int,
        w: int,
        h: int,
        pins: int,
        body: tuple[int, int, int],
        edge: tuple[int, int, int],
    ) -> None:
        """Draw an integrated-circuit glyph with edge pins.

        Parameters
        ----------
        cx : int
            The horizontal center of the chip body.
        cy : int
            The vertical center of the chip body.
        w : int
            The chip body width in columns.
        h : int
            The chip body height in rows.
        pins : int
            The number of edge pins per side.
        body : tuple[int, int, int]
            The RGB chip body color.
        edge : tuple[int, int, int]
            The RGB border and pin color.

        Returns
        -------
        None
        """
        half_w, half_h = w // 2, h // 2
        left, top = cx - half_w, cy - half_h
        self.fill_rect(left, top, w, h, body)
        self.rect_border(left, top, w, h, 8, edge)
        seg = w // (pins + 1)
        for n in range(1, pins + 1):
            px = left + n * seg
            self.fill_rect(px, top - 30, 10, 30, edge)
            self.fill_rect(px, top + h, 10, 30, edge)
        vseg = h // (pins + 1)
        for n in range(1, pins + 1):
            py = top + n * vseg
            self.fill_rect(left - 30, py, 30, 10, edge)
            self.fill_rect(left + w, py, 30, 10, edge)

    def save(self, path: Path) -> None:
        """Encode the canvas as a PNG file and write it to disk.

        Parameters
        ----------
        path : Path
            The destination path for the PNG artifact.

        Returns
        -------
        None
        """
        data = bytearray()
        for row in self.frame:
            data.append(0)
            for px in row:
                data += bytes(px)
        def chunk(tag: bytes, payload: bytes) -> bytes:
            """Encode one PNG chunk with its CRC.

            Parameters
            ----------
            tag : bytes
                The four-byte chunk type.
            payload : bytes
                The chunk data payload.

            Returns
            -------
            bytes
                The length-prefixed tagged chunk with trailing CRC.
            """
            c = struct.pack(">I", len(payload)) + tag + payload
            return c + struct.pack(">I", zlib.crc32(tag + payload))
        ihdr = struct.pack(">IIBBBBB", self.W, self.H, 8, 2, 0, 0, 0)
        png = (
            b"\x89PNG\r\n\x1a\n"
            + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(bytes(data), 9))
            + chunk(b"IEND", b"")
        )
        path.write_bytes(png)


def _palette() -> dict:
    """Return the banner color palette.

    Parameters
    ----------
    None

    Returns
    -------
    dict
        Named RGB color tuples.
    """
    return {"silver": (0xD8, 0xDE, 0xE9), "gold": (0xE8, 0xB8, 0x4B),
            "cyan": (0x7F, 0xD8, 0xE0), "white": (0xF2, 0xF5, 0xFF),
            "dim": (0x9A, 0xA4, 0xB8)}


def _draw_titles(banner, colors) -> None:
    """Draw the product title block and chip outline.

    Parameters
    ----------
    banner : Banner
        Banner drawing surface.
    colors : dict
        Named RGB color tuples.

    Returns
    -------
    None
    """
    banner.text("ACCESS GATE & VAULT CONTROL", 4,
                colors["gold"], banner.W // 2, 90)
    banner.text("OPERATION IRON GATE", 10, (0x0B, 0x10, 0x26),
                banner.W // 2 - 6, 176)
    banner.text("OPERATION IRON GATE", 10, colors["white"],
                banner.W // 2, 182)
    banner.text("RP2350  PICO 2", 5, colors["cyan"], banner.W // 2, 560)
    banner.text("-=[ ACCESS CONTROL DEFENSE + HACKING LAB ]=-", 3, colors["dim"],
                banner.W // 2, 660)
    banner.chip(banner.W // 2, 880, 820, 300, 14, (0x09, 0x12, 0x1E),
                colors["silver"])


def _draw_features(banner, colors) -> None:
    """Draw the feature list and footer text.

    Parameters
    ----------
    banner : Banner
        Banner drawing surface.
    colors : dict
        Named RGB color tuples.

    Returns
    -------
    None
    """
    banner.text("ACCESS_GATE", 6, colors["cyan"], banner.W // 2, 760)
    banner.text("RP2350", 5, colors["gold"], banner.W // 2, 880)
    banner.text("IR KEYPAD  SERVO DEADBOLT  DHT11", 3, colors["silver"],
                banner.W // 2, 960)
    banner.text("VS1838B  SG90  I2C LCD  RYLR998", 4,
                colors["silver"], banner.W // 2, 1160)
    banner.text("XCHACHA20-POLY1305  ARGON2ID  ANTI-REPLAY", 3,
                colors["dim"], banner.W // 2, 1260)
    banner.text("AUTHENTICATED STATE  FAIL-SECURE", 4, colors["gold"],
                banner.W // 2, 1350)
    banner.text("-=[ OPERATION IRON GATE  /  RP2350 ]=-", 3, colors["dim"],
                banner.W // 2, 1440)


def main() -> int:
    """Draw every banner element and write the PNG artifact.

    Parameters
    ----------
    None

    Returns
    -------
    int
        The process exit code; zero on success.
    """
    banner = Banner()
    colors = _palette()
    _draw_titles(banner, colors)
    _draw_features(banner, colors)
    out = Path(__file__).resolve().parent.parent / "access-gate.png"
    banner.save(out)
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    sys.exit(main())