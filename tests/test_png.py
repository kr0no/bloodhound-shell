from __future__ import annotations

import struct
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest

from bhshell.queries.paths import PathResult
from bhshell.render import png, svg
from bhshell.shell.app import BHShell
from tests.conftest import run
from tests.test_svg import A, B, C, chain


def chunks(data: bytes) -> list[tuple[bytes, bytes]]:
    out, pos = [], 8
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        out.append((data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]))
        pos += 12 + length
    return out


def dimensions(data: bytes) -> tuple[int, int]:
    return struct.unpack(">II", chunks(data)[0][1][:8])


def test_png_is_rendered_at_scale_and_tagged_with_matching_dpi() -> None:
    doc = svg.render(PathResult("t", paths=[chain(A, "MemberOf", B, "GenericAll", C)]))
    data = png.from_svg(doc, 2.0)
    root = ET.fromstring(doc)
    width, height = float(root.get("width", 0)), float(root.get("height", 0))
    assert dimensions(data) == (round(width * 2), round(height * 2))
    kinds = [k for k, _ in chunks(data)]
    assert kinds[:2] == [b"IHDR", b"pHYs"] and kinds.count(b"pHYs") == 1 and kinds[-1] == b"IEND"
    ppm_x, ppm_y, unit = struct.unpack(">IIB", dict(chunks(data))[b"pHYs"])
    assert unit == 1 and ppm_x == ppm_y and round(ppm_x / 39.3701) == 192  # Word: same size as the SVG


def test_with_dpi_replaces_an_existing_phys_chunk() -> None:
    ihdr = png._chunk(b"IHDR", struct.pack(">IIBBBBB", 1, 1, 8, 6, 0, 0, 0))
    old = png._chunk(b"pHYs", struct.pack(">IIB", 2835, 2835, 1))
    data = png._SIGNATURE + ihdr + old + png._chunk(b"IEND", b"")
    out = png.with_dpi(data, 300)
    assert [k for k, _ in chunks(out)] == [b"IHDR", b"pHYs", b"IEND"]
    assert struct.unpack(">IIB", dict(chunks(out))[b"pHYs"])[0] == round(300 * 39.3701)
    with pytest.raises(ValueError):
        png.with_dpi(b"GIF89a", 96)


def test_path_exports_png(shell: BHShell, tmp_path: Path) -> None:
    run(shell, "login -u admin")
    target = tmp_path / "owned.png"
    out = run(shell, f"path --owned -o {target} --png-scale 3")
    assert "written to" in out and target.read_bytes().startswith(png._SIGNATURE)
    ppm = struct.unpack(">IIB", dict(chunks(target.read_bytes()))[b"pHYs"])[0]
    assert round(ppm / 39.3701) == 288
    before = shell.command_failures
    run(shell, f"path --owned -o {target} --png-scale 20")  # usage error (out of range)
    assert shell.command_failures == before + 1
