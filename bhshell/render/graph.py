"""Attack paths drawn as a graph with box-drawing characters, top to bottom.

Every layer of `Layout` becomes a row of boxes. Below each
row, every link gets its own horizontal track: it leaves its source from the bottom
centre, runs along the track and drops into the top centre of its target. Line pieces are
recorded as directions per cell and turned into the right junction characters at the end,
so shared stubs merge into trees (fan-out) and arrows into the same box join (fan-in).
"""

from __future__ import annotations

import itertools
from collections import defaultdict
from dataclasses import dataclass

from rich.text import Text

from bhshell.models.entities import Node
from bhshell.queries.edges import SEVERITIES, severity, severity_rank
from bhshell.queries.paths import AttackPath, PathResult
from bhshell.render.layout import Layout, Link, split_name
from bhshell.render.styles import KIND_STYLE, SEVERITY_STYLE

MIN_GAP = 4  # columns between boxes

UP, DOWN, LEFT, RIGHT = 1, 2, 4, 8
JUNCTION = {
    UP: "│", DOWN: "│", UP | DOWN: "│", LEFT: "─", RIGHT: "─", LEFT | RIGHT: "─",
    DOWN | RIGHT: "╭", DOWN | LEFT: "╮", UP | RIGHT: "╰", UP | LEFT: "╯",
    UP | DOWN | RIGHT: "├", UP | DOWN | LEFT: "┤", LEFT | RIGHT | DOWN: "┬", LEFT | RIGHT | UP: "┴",
    UP | DOWN | LEFT | RIGHT: "┼",
}
ROUND = "╭╮╰╯─│"
DOUBLE = "╔╗╚╝═║"


class _Canvas:
    def __init__(self, width: int, height: int) -> None:
        self.width, self.height = width, height
        self.chars = [[" "] * width for _ in range(height)]
        self.styles = [[""] * width for _ in range(height)]
        self.dirs = [[0] * width for _ in range(height)]

    def put(self, x: int, y: int, text: str, style: str = "") -> None:
        for i, char in enumerate(text):
            self.chars[y][x + i] = char
            self.styles[y][x + i] = style
            self.dirs[y][x + i] = 0

    def vline(self, x: int, y0: int, y1: int, style: str) -> None:
        for y in range(y0, y1 + 1):
            self.dirs[y][x] |= (UP if y > y0 else 0) | (DOWN if y < y1 else 0)
            self.styles[y][x] = style

    def hline(self, y: int, x0: int, x1: int, style: str) -> None:
        a, b = sorted((x0, x1))
        for x in range(a, b + 1):
            self.dirs[y][x] |= (LEFT if x > a else 0) | (RIGHT if x < b else 0)
            self.styles[y][x] = style

    def free(self, x: int, y: int, length: int) -> bool:
        """True if `length` cells from `(x, y)` are inside the canvas and hold nothing."""
        if x < 0 or x + length > self.width:
            return False
        return all(self.chars[y][i] == " " and not self.dirs[y][i] for i in range(x, x + length))

    def crossable(self, x: int, y: int, length: int) -> bool:
        """True if the cells only hold horizontal line pieces (a label may be written over them)."""
        if x < 0 or x + length > self.width:
            return False
        return all(self.chars[y][i] == " " and not self.dirs[y][i] & (UP | DOWN) for i in range(x, x + length))

    def lines(self) -> list[Text]:
        out = []
        for chars, styles, dirs in zip(self.chars, self.styles, self.dirs, strict=True):
            text = Text()
            for char, style, d in zip(chars, styles, dirs, strict=True):
                text.append(JUNCTION.get(d, char) if d else char, style=style)
            text.rstrip()
            out.append(text)
        return out


@dataclass
class _Segment:
    """One link (or one stretch of a long link) between two adjacent layers."""

    link: Link
    x_from: int
    x_to: int
    into_box: bool        # ends on a real node (arrow) rather than a lane point
    label: str            # '' on the continuation stretches of a long link
    style: str
    track: int = 0


def draw(result: PathResult, paths: list[AttackPath], max_width: int) -> tuple[list[Text], list[str]]:
    """Graph lines for `paths` and extra notes (links that loop back, labels moved to footnotes).

    Wider spacing leaves room to write labels next to their lines, so gaps from generous down to
    the minimum are tried and the drawing with the fewest footnotes that fits `max_width` wins
    (the narrowest one if none fits).
    """
    layout = Layout(paths)
    widest_label = max(len(", ".join(link.kinds)) for link in layout.links.values())
    best: tuple[int, int, list[Text], list[str]] | None = None
    for gap in range(widest_label + 4, MIN_GAP - 1, -2):
        lines, notes = _draw(result, layout, max(gap, MIN_GAP))
        width = max(line.cell_len for line in lines)
        footnotes = sum(note.startswith("[") for note in notes)
        if width <= max_width and (best is None or footnotes < best[0]):
            best = (footnotes, width, lines, notes)
        if best is not None and best[0] == 0:
            break
    if best is None:
        return _draw(result, layout, MIN_GAP)
    return best[2], best[3]


def _draw(result: PathResult, layout: Layout, gap: int) -> tuple[list[Text], list[str]]:
    waypoints = set(result.waypoints)
    domains = {tail for _, tail in (split_name(n) for n in layout.nodes.values())}
    short = len(domains) == 1  # one domain: leave it out of every box

    boxes = {key: _box_text(node, short, node.objectid in waypoints) for key, node in layout.nodes.items()}
    width_of = {key: (boxes[key].cell_len + 4 if key in boxes else 1) for key in layout.layer}

    left = _place(layout, width_of, gap)
    port = {key: left[key] + width_of[key] // 2 for key in layout.layer}
    total_width = max(left[key] + width_of[key] for key in left)

    # Segments per band (band i lies between layer i and layer i + 1), each on its own track.
    bands: list[list[_Segment]] = [[] for _ in layout.columns]
    for link in sorted(layout.links.values(), key=lambda l: -_order(l.kinds)):
        if link.back:
            continue
        for i, (a, b) in enumerate(itertools.pairwise(link.lane)):
            bands[layout.layer[a]].append(_Segment(
                link, port[a], port[b], b in layout.nodes, ", ".join(link.kinds) if i == 0 else "",
                SEVERITY_STYLE.get(_worst(link.kinds), "")))
    for band in bands:
        # Tracks: links heading left take the upper tracks, links heading right the lower ones,
        # each group ordered so their horizontals nest instead of crossing.
        band.sort(key=lambda s: (s.x_to >= s.x_from, -s.x_from if s.x_to < s.x_from else s.x_from,
                                 s.x_to if s.x_to < s.x_from else -s.x_to))
        for track, segment in enumerate(band):
            segment.track = track

    # Vertical placement: 3 rows per layer, then one row per track and one for the arrows.
    top: list[int] = []
    y = 0
    for band in bands:
        top.append(y)
        y += 3 + (len(band) + 1 if band else 0)
    canvas = _Canvas(total_width + 40, y)  # spare room on the right for labels

    for key, node in layout.nodes.items():
        _draw_box(canvas, left[key], top[layout.layer[key]], boxes[key], node, node.objectid in waypoints,
                  has_out=any(l.source == key and not l.back for l in layout.links.values()))
    for link in layout.links.values():
        for key in link.lane[1:-1]:
            canvas.vline(port[key], top[layout.layer[key]], top[layout.layer[key]] + 2,
                         SEVERITY_STYLE.get(_worst(link.kinds), ""))
    for i, band in enumerate(bands):
        for s in band:
            track_y = top[i] + 3 + s.track
            arrow_y = top[i + 1] - 1
            canvas.vline(s.x_from, top[i] + 3, track_y, s.style)
            canvas.dirs[top[i] + 3][s.x_from] |= UP  # joins the ┬ of the source box (or a lane line)
            canvas.hline(track_y, s.x_from, s.x_to, s.style)
            canvas.vline(s.x_to, track_y, arrow_y, s.style)
            if s.into_box:
                canvas.put(s.x_to, arrow_y, "▼", s.style)
            else:
                canvas.dirs[arrow_y][s.x_to] |= DOWN

    notes = _place_labels(canvas, bands, top)
    for link in layout.links.values():
        if link.back:
            a, b = layout.nodes[link.source], layout.nodes[link.target]
            notes.append(f"↺ {a.name} ─{', '.join(link.kinds)}→ {b.name} (back to an earlier step)")
    lines = canvas.lines()
    width = max(line.cell_len for line in lines)
    return [line[:width] for line in lines], notes


def _place(layout: Layout, width_of: dict[str, int], gap: int) -> dict[str, int]:
    """Left column of every box: each one under the mean port of its parents (and parents over their
    children), keeping the layer order and at least `gap` columns between boxes."""
    parents: dict[str, list[str]] = defaultdict(list)
    children: dict[str, list[str]] = defaultdict(list)
    for link in layout.links.values():
        if not link.back:
            for a, b in itertools.pairwise(link.lane):
                children[a].append(b)
                parents[b].append(a)
    left: dict[str, int] = {}
    for col in layout.columns:
        x = 0
        for key in col:
            left[key] = x
            x += width_of[key] + gap

    def align(col: list[str], neighbours: dict[str, list[str]]) -> None:
        wanted = {}
        for key in col:
            ports = [left[n] + width_of[n] // 2 for n in neighbours[key]]
            wanted[key] = round(sum(ports) / len(ports)) - width_of[key] // 2 if ports else left[key]
        # Boxes that would overlap form a block, centred on where its members want to be.
        blocks: list[tuple[list[str], list[int], int]] = []  # (keys, offsets in the block, start)
        for key in col:
            blocks.append(([key], [0], wanted[key]))
            while len(blocks) > 1:
                (keys_a, offs_a, start_a), (keys_b, offs_b, start_b) = blocks[-2:]
                base = offs_a[-1] + width_of[keys_a[-1]] + gap
                if start_a + base <= start_b:
                    break
                keys, offsets = keys_a + keys_b, offs_a + [base + o for o in offs_b]
                start = round(sum(wanted[k] - o for k, o in zip(keys, offsets, strict=True)) / len(keys))
                blocks[-2:] = [(keys, offsets, start)]
        for keys, offsets, start in blocks:
            for key, offset in zip(keys, offsets, strict=True):
                left[key] = start + offset

    for _ in range(2):
        for col in layout.columns[1:]:
            align(col, parents)
        for col in reversed(layout.columns[:-1]):
            align(col, children)
    for col in layout.columns[1:]:
        align(col, parents)
    shift = min(left.values())
    return {key: x - shift for key, x in left.items()}


def _place_labels(canvas: _Canvas, bands: list[list[_Segment]], top: list[int]) -> list[str]:
    """Write each link's right names next to its line; whatever does not fit becomes a footnote."""
    notes: list[str] = []
    for i, band in enumerate(bands):
        for s in sorted((s for s in band if s.label), key=lambda s: _order(s.link.kinds)):
            track_y = top[i] + 3 + s.track
            text = f" {s.label} "
            a, b = sorted((s.x_from, s.x_to))
            candidates = []
            if b - a - 1 >= len(text):  # on the horizontal stretch, centred
                candidates.append(((a + b + 1 - len(text)) // 2, track_y, canvas.crossable))
            # Otherwise beside the drop into the target, then beside the stub leaving the source.
            for y in range(track_y, top[i + 1] - 1):
                candidates += [(s.x_to + 1, y, canvas.free), (s.x_to - len(text), y, canvas.free)]
            for y in range(track_y, top[i] + 2, -1):
                candidates += [(s.x_from + 1, y, canvas.free), (s.x_from - len(text), y, canvas.free)]
            for x, y, fits in candidates:
                if fits(x, y, len(text)):
                    canvas.put(x, y, text, f"bold {s.style}".strip())
                    break
            else:
                marker = f"[{len(notes) + 1}]"
                for x in (s.x_to + 1, s.x_to - len(marker)):
                    if canvas.free(x, track_y, len(marker)):
                        canvas.put(x, track_y, marker, f"bold {s.style}".strip())
                        break
                notes.append(f"{marker} {s.label}")
    return notes


def _box_text(node: Node, short: bool, waypoint: bool) -> Text:
    head, tail = split_name(node)
    name = head if short or not tail else node.name
    text = Text.assemble(("● ", KIND_STYLE.get(node.kind, "white")), (name, "bold"))
    if node.tier_zero:
        text.append(" ").append("T0", style="bold white on red")
    if node.owned:
        text.append(" ").append("OWNED", style="bold white on blue")
    if waypoint:
        text.append(" ").append("via", style="bold")
    return text


def _draw_box(canvas: _Canvas, x: int, y: int, text: Text, node: Node, waypoint: bool, has_out: bool) -> None:
    tl, tr, bl, br, h, v = DOUBLE if waypoint else ROUND
    border = "bold red" if node.tier_zero else "bold blue" if node.owned else "bright_black"
    inner = text.cell_len + 2
    canvas.put(x, y, tl + h * inner + tr, border)
    canvas.put(x, y + 1, v, border)
    for offset, span in enumerate(_cells(text)):
        canvas.put(x + 2 + offset, y + 1, span[0], span[1])
    canvas.put(x + 2 + text.cell_len, y + 1, " " + v, border)
    canvas.put(x + 1, y + 1, " ")
    bottom = bl + h * inner + br
    if has_out:
        mid = (inner + 2) // 2
        bottom = bottom[:mid] + "┬" + bottom[mid + 1:]
    canvas.put(x, y + 2, bottom, border)


def _cells(text: Text) -> list[tuple[str, str]]:
    """`(char, style)` for every character of `text`."""
    styles = [""] * len(text.plain)
    for span in text.spans:
        for i in range(span.start, span.end):
            styles[i] = str(span.style)
    return list(zip(text.plain, styles, strict=True))


def _order(kinds: list[str]) -> int:
    return min(map(severity_rank, kinds))


def _worst(kinds: list[str]) -> str:
    return SEVERITIES[_order(kinds)]


def legend(paths: list[AttackPath], waypoints: bool) -> Text:
    layout_kinds = {n.kind for p in paths for h in p.hops for n in (h.source, h.target)}
    text = Text()
    for kind, style in KIND_STYLE.items():
        if kind in layout_kinds:
            text.append("● ", style=style).append(f"{kind}  ", style="dim")
    present = {severity(h.edge) for p in paths for h in p.hops}
    for level, style in SEVERITY_STYLE.items():
        if level in present:
            text.append("── ", style=style).append(f"{level}  ", style="dim")
    if waypoints:
        text.append("╔═╗", style="bright_black").append(" waypoint (--via)", style="dim")
    text.rstrip()
    return text
