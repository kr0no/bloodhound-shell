"""PNG export of the SVG diagrams, rasterised with resvg.

The image is rendered at `scale` times the SVG size and tagged with `96 * scale` dpi, so Word
inserts it at the same physical size as the SVG while keeping it sharp when printed.
"""

from __future__ import annotations

import struct
import zlib

import resvg_py

_SIGNATURE = b"\x89PNG\r\n\x1a\n"
_INCH_PER_METRE = 39.3701


def from_svg(svg: str, scale: float = 2.0) -> bytes:
    """PNG bytes for an SVG document, on a white background."""
    png = bytes(resvg_py.svg_to_bytes(svg_string=svg, zoom=scale, background="#ffffff"))
    return with_dpi(png, 96 * scale)


def _chunk(kind: bytes, data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))


def with_dpi(png: bytes, dpi: float) -> bytes:
    """`png` with its physical resolution (`pHYs` chunk) set to `dpi`, replacing any existing one."""
    if not png.startswith(_SIGNATURE):
        raise ValueError("not a PNG image")
    ppm = round(dpi * _INCH_PER_METRE)
    phys = _chunk(b"pHYs", struct.pack(">IIB", ppm, ppm, 1))
    out, pos = [_SIGNATURE], len(_SIGNATURE)
    while pos < len(png):
        (length,) = struct.unpack(">I", png[pos:pos + 4])
        kind = png[pos + 4:pos + 8]
        end = pos + 12 + length
        if kind != b"pHYs":
            out.append(png[pos:end])
        if kind == b"IHDR":  # pHYs must come before the image data; right after the header is safe
            out.append(phys)
        pos = end
    return b"".join(out)
