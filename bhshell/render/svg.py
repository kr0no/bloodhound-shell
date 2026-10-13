"""Attack paths as an SVG diagram, for reports.

The paths are laid out by `bhshell.render.layout`, left to right or top to bottom, whichever
prints larger on a portrait Word page. Only plain shapes with inline attributes are
used (no CSS, markers or filters) so the file renders the same in browsers and in Word.
"""

from __future__ import annotations

import itertools
from collections import Counter
from typing import Literal, NamedTuple
from xml.sax.saxutils import escape, quoteattr

from bhshell.models.entities import Node
from bhshell.queries.edges import SEVERITIES, severity
from bhshell.queries.paths import AttackPath, PathResult
from bhshell.render.layout import Layout, Link, split_name

FONT = "Segoe UI, Helvetica Neue, Arial, sans-serif"
INK = "#1f2933"
MUTED = "#6b7785"
KIND_COLOR = {
    "User": "#2e9e5b", "Computer": "#d9534f", "Group": "#c79a00", "Domain": "#12a08a",
    "GPO": "#7b68d9", "OU": "#e08a00", "Container": "#c9704f",
}
SEVERITY_COLOR = {"critical": "#c62828", "high": "#e65100", "medium": "#a07800"}
T0_COLOR = "#c62828"
OWNED_COLOR = "#1565c0"

R = 24                 # node radius
NODE_SLOT = 104        # vertical room for a node and its caption
LANE_SLOT = 40         # vertical room for a long link passing through a column
MARGIN = 36
HEADER = 16            # space above the top nodes (their badges have their own room)
LABEL_FS = 13          # edge label font size
MIN_PER_ROW = 3        # a wrapped row holds at least this many nodes, so it still reads as a path
LEGEND_MIN = 420       # the legend wraps at the diagram width, but not narrower than this
# Word's text area on a portrait Letter/A4 page with normal margins (6.5 x 9 in), in px at 96 dpi.
PAGE = (624, 864)

Orientation = Literal["auto", "horizontal", "vertical", "wrapped"]


class Pill(NamedTuple):
    """An edge label. Labels sharing a `gap` (between two columns or rows) are kept from overlapping."""

    gap: int  # -1 for back links
    x: float
    y: float
    kinds: list[str]


class Drawing(NamedTuple):
    pos: dict[str, tuple[float, float]]
    edges: list[str]
    pills: list[Pill]
    right: float
    bottom: float


def _text_width(text: str, size: float, bold: bool = False) -> float:
    """Rough rendered width; good enough to size columns and label pills."""
    return len(text) * size * (0.64 if bold else 0.55)


def page_fit(width: float, height: float, page: tuple[float, float] = PAGE) -> float:
    """Scale at which a `width` x `height` picture fits the page (1 = native size or smaller)."""
    return min(1.0, page[0] / width, page[1] / height)


def render(result: PathResult, paths: list[AttackPath] | None = None, orientation: Orientation = "auto") -> str:
    """SVG document for `paths` (default: every path of `result`).

    `auto` tries horizontal, vertical and every wrapped row length, and keeps whichever prints
    largest on a portrait page; near ties go to the simpler one. `wrapped` tries only wrapped rows.
    """
    paths = result.paths if paths is None else paths
    if not paths:
        return _document(240, 80, [_text(MARGIN, 46, "No path found.", 14, MUTED)])
    if orientation in ("horizontal", "vertical"):
        return _document(*_diagram(result, paths, vertical=orientation == "vertical"))
    layers = len(Layout(paths).columns)
    candidates = [] if orientation == "wrapped" else [_diagram(result, paths, vertical=False),
                                                      _diagram(result, paths, vertical=True)]
    candidates += [_diagram(result, paths, vertical=False, per_row=n) for n in range(layers - 1, MIN_PER_ROW - 1, -1)]
    if not candidates:  # too short to wrap
        return _document(*_diagram(result, paths, vertical=False))
    best = candidates[0]
    for candidate in candidates[1:]:
        if page_fit(*candidate[:2]) > page_fit(*best[:2]) + 0.03:
            best = candidate
    return _document(*best)


def _diagram(result: PathResult, paths: list[AttackPath], *, vertical: bool,
             per_row: int | None = None) -> tuple[float, float, list[str]]:
    """Width, height and elements of the whole picture: the paths and the legend."""
    layout = Layout(paths)
    labels = {key: split_name(node) for key, node in layout.nodes.items()}
    domains = {tail for _, tail in labels.values()}
    single_domain = domains.pop() if len(domains) == 1 else ""
    if single_domain:  # the report around the picture names the domain; keep the captions short
        labels = {key: (head, "") for key, (head, _) in labels.items()}

    pos, edges, pills, right, bottom = (_vertical(layout, labels) if vertical
                                        else _horizontal(layout, labels, per_row))
    spread = _spread(pills, horizontal=vertical)
    right = max([right, *(x + _pill_width(kinds) / 2 for x, _, kinds in spread)])

    legend_width_cap = max(right - MARGIN, LEGEND_MIN) if vertical else float("inf")
    legend, legend_width, legend_height = _legend(MARGIN, bottom + 16, layout, bool(result.waypoints),
                                                  legend_width_cap)
    width = max(right + MARGIN, legend_width + 2 * MARGIN)
    height = bottom + 16 + legend_height + 16
    waypoints = set(result.waypoints)
    nodes = [_node(layout.nodes[key], pos[key], labels[key], layout.nodes[key].objectid in waypoints)
             for key in layout.nodes]
    parts = edges + nodes + [svg for pill in spread for svg in _pill(*pill)] + legend
    return width, height, parts


def _caption_width(label: tuple[str, str]) -> float:
    return max(_text_width(label[0], 13, True), _text_width(label[1], 11))


def _caption_depth(label: tuple[str, str]) -> float:
    """How far a node and its caption reach below the node's centre."""
    return R + (40 if label[1] else 26)


def _color(link: Link) -> str:
    return SEVERITY_COLOR.get(min((severity(k) for k in link.kinds), key=SEVERITIES.index), MUTED)


def _horizontal(layout: Layout, labels: dict[str, tuple[str, str]], per_row: int | None = None) -> Drawing:
    """Columns left to right, by hop distance; `per_row` columns per row, wrapping like lines of text."""
    columns = layout.columns
    per_row = per_row or len(columns)
    rows = [list(range(i, min(i + per_row, len(columns)))) for i in range(0, len(columns), per_row)]
    row_of = {col: r for r, cols in enumerate(rows) for col in cols}
    # Column widths fit the node captions; gaps fit the edge labels leaving that column.
    col_width = [max(2 * R + 16, *(_caption_width(labels[k]) for k in col if k in labels)) for col in columns]
    gaps = [0.0] * len(columns)
    forward = [link for link in layout.links.values() if not link.back]
    for link in forward:
        col = layout.layer[link.source]
        gaps[col] = max(gaps[col], _pill_width(link.kinds) + 56)
    x_center, right = [0.0] * len(columns), float(MARGIN)
    for cols in rows:
        x = MARGIN
        for j, col in enumerate(cols):
            x_center[col] = x + col_width[col] / 2
            x += col_width[col] + (gaps[col] if j < len(cols) - 1 else 0)
        right = max(right, x)

    # A link into a later row leaves through the channel under its own row; one skipping rows also
    # runs down the left gutter to the channel above its target. Its lane points are not drawn.
    def row(key: str) -> int:
        return row_of[layout.layer[key]]

    wraps: list[list[tuple[Link, str]]] = [[] for _ in rows]
    gutter: dict[int, float] = {}
    unused: set[str] = set()
    for link in forward:
        rs, rt = row(link.source), row(link.target)
        if rs != rt:
            wraps[rs].append((link, "out"))
            if rt - rs > 1:
                wraps[rt - 1].append((link, "in"))
                gutter[id(link)] = MARGIN / 2 - 6 * len(gutter)
            unused.update(link.lane[1:-1])

    # Stack each column (nodes need more room than lanes), centre the columns of a row on each other,
    # and leave room under a row for the wrapping links, one level each so their labels never overlap.
    slot = {key: LANE_SLOT if key in layout.virtual else NODE_SLOT for key in layout.layer}
    heights = [sum(slot[k] for k in col if k not in unused) for col in columns]
    back_room = 40 if any(link.back for link in layout.links.values()) else 0
    pos: dict[str, tuple[float, float]] = {}
    run_y: dict[tuple[int, str], float] = {}
    top = float(HEADER)
    for r, cols in enumerate(rows):
        body = max(max(heights[c] for c in cols), NODE_SLOT)
        for col in cols:
            y = top + (body - heights[col]) / 2
            for key in columns[col]:
                if key in unused:
                    continue
                pos[key] = (x_center[col], y + (R + 12 if key in labels else slot[key] / 2))
                y += slot[key]
        top += body + back_room
        if wraps[r]:
            top += 10
            for link, end in wraps[r]:
                h = _pill_height(link.kinds)
                run_y[(id(link), end)] = top + h / 2
                top += h + 8
            top += 18

    edges: list[str] = []
    pills: list[Pill] = []
    for link in layout.links.values():
        color = _color(link)
        (x1, y1), (x2, y2) = pos[link.source], pos[link.target]
        if link.back:  # loop back under the nodes
            low = max(y1, y2) + R + 46
            d = f"M{x1:.1f},{y1 + R:.1f} C{x1:.1f},{low:.1f} {x2:.1f},{low:.1f} {x2:.1f},{y2 + R + 9:.1f}"
            pills.append(Pill(-1, (x1 + x2) / 2, low - 8, link.kinds))
            edges += [_stroke(d, color), _arrow(x2, y2 + R, "up", color)]
            continue
        if (id(link), "out") in run_y:
            # Into a later row: down to the channel under this row, across, and down into the target.
            # A link skipping rows goes along the left gutter to the channel above the target's row.
            ry = run_y[(id(link), "out")]
            gx = gutter.get(id(link))
            d = f"M{x1:.1f},{y1 + _caption_depth(labels[link.source]):.1f}" + _corner(x1, ry, x2 if gx is None else gx)
            if gx is not None:
                ry2 = run_y[(id(link), "in")]
                d += f" L{gx:.1f},{ry2 - 12:.1f} Q{gx:.1f},{ry2:.1f} {gx + 12:.1f},{ry2:.1f}"
                d += _corner(gx, ry2, x2, entering=True)
            # Each wrapping link has its own channel, so its label gets a gap of its own.
            pills.append(Pill(10_000 + len(pills), (x1 + (MARGIN if gx is not None else x2)) / 2, ry, link.kinds))
            d += f" L{x2:.1f},{y2 - R - 9:.1f}"
            edges += [_stroke(d, color), _arrow(x2, y2 - R, "down", color)]
            continue
        # Horizontal entry/exit points for each column on the lane, joined by S-curves across the gaps.
        stops: list[tuple[float, float, float]] = []  # (x in, x out, y)
        for key in link.lane:
            kx, ky = pos[key]
            half = col_width[layout.layer[key]] / 2 if key in layout.virtual else R
            stops.append((kx - half, kx + half, ky))
        d = f"M{stops[0][1]:.1f},{stops[0][2]:.1f}"
        for i, ((_, out_x, ya), (in_x, next_out, yb)) in enumerate(itertools.pairwise(stops)):
            end = in_x - 9 if i == len(stops) - 2 else in_x
            dx = (end - out_x) / 2
            d += f" C{out_x + dx:.1f},{ya:.1f} {end - dx:.1f},{yb:.1f} {end:.1f},{yb:.1f}"
            if i < len(stops) - 2:
                d += f" L{next_out:.1f},{yb:.1f}"
        # Label in the middle of the first gap, where the S-curve crosses halfway.
        col = layout.layer[link.source]
        pills.append(Pill(col, x_center[col] + col_width[col] / 2 + gaps[col] / 2,
                          (stops[0][2] + stops[1][2]) / 2, link.kinds))
        edges += [_stroke(d, color), _arrow(x2 - R, y2, "right", color)]
    return Drawing(pos, edges, pills, right, top)


def _corner(x: float, y: float, to_x: float, *, entering: bool = False) -> str:
    """Path from heading down at `x` (or, `entering`, heading sideways at `y`) along `y` to `to_x`,
    turning down there. Corners are rounded."""
    turn = -12 if to_x < x else 12
    head = "" if entering else f" L{x:.1f},{y - 12:.1f} Q{x:.1f},{y:.1f} {x + turn:.1f},{y:.1f}"
    return head + f" L{to_x - turn:.1f},{y:.1f} Q{to_x:.1f},{y:.1f} {to_x:.1f},{y + 12:.1f}"


def _vertical(layout: Layout, labels: dict[str, tuple[str, str]]) -> Drawing:
    """Rows top to bottom, by hop distance; captions under the nodes, edges leave below the captions."""
    rows = layout.columns
    # Labels sit next to a node at a fan's wide end, so a node's slot fits its caption and its edge labels.
    label_width: dict[str, float] = {}
    for link in layout.links.values():
        if not link.back:
            for key in (link.source, link.target):
                label_width[key] = max(label_width.get(key, 0.0), _pill_width(link.kinds))
    slot = {key: LANE_SLOT if key in layout.virtual else
            max(2 * R + 16, _caption_width(labels[key]), label_width.get(key, 0.0)) + 20 for key in layout.layer}
    has_nodes = [any(k in labels for k in row) for row in rows]
    above = [R + 12 if real else LANE_SLOT / 2 for real in has_nodes]
    below = [max((_caption_depth(labels[k]) for k in row if k in labels), default=LANE_SLOT / 2) for row in rows]
    gaps = [56.0] * len(rows)
    for link in layout.links.values():
        if not link.back:
            row = layout.layer[link.source]
            gaps[row] = max(gaps[row], _pill_height(link.kinds) + 44)
    y_center, y = [], HEADER
    for i in range(len(rows)):
        y_center.append(y + above[i])
        y += above[i] + below[i] + (gaps[i] if i < len(rows) - 1 else 0)

    widths = [sum(slot[k] for k in row) for row in rows]
    body = max(*widths, LEGEND_MIN)  # centred over the legend
    pos: dict[str, tuple[float, float]] = {}
    for i, row in enumerate(rows):
        x = MARGIN + (body - widths[i]) / 2
        for key in row:
            pos[key] = (x + slot[key] / 2, y_center[i])
            x += slot[key]

    forward = [link for link in layout.links.values() if not link.back]
    fan_out = Counter(link.source for link in forward)
    fan_in = Counter(link.target for link in forward)
    right = MARGIN + body
    edges: list[str] = []
    pills: list[Pill] = []
    for link in layout.links.values():
        color = _color(link)
        (x1, y1), (x2, y2) = pos[link.source], pos[link.target]
        if link.back:  # loop back on the right of the nodes
            side = max(x1, x2) + max(slot[link.source], slot[link.target]) / 2 + 30
            d = f"M{x1 + R:.1f},{y1:.1f} C{side:.1f},{y1:.1f} {side:.1f},{y2:.1f} {x2 + R + 9:.1f},{y2:.1f}"
            pills.append(Pill(-1, side - 8, (y1 + y2) / 2, link.kinds))
            right = max(right, side + _pill_width(link.kinds) / 2)
            edges += [_stroke(d, color), _arrow(x2 + R, y2, "left", color)]
            continue
        stops: list[tuple[float, float, float]] = []  # (y in, y out, x)
        for key in link.lane:
            kx, ky = pos[key]
            row = layout.layer[key]
            if key in layout.virtual:
                stops.append((ky - above[row], ky + below[row], kx))
            else:
                stops.append((ky - R, ky + _caption_depth(labels[key]), kx))
        d = f"M{stops[0][2]:.1f},{stops[0][1]:.1f}"
        for i, ((_, out_y, xa), (in_y, next_out, xb)) in enumerate(itertools.pairwise(stops)):
            end = in_y - 9 if i == len(stops) - 2 else in_y
            dy = (end - out_y) / 2
            d += f" C{xa:.1f},{out_y + dy:.1f} {xb:.1f},{end - dy:.1f} {xb:.1f},{end:.1f}"
            if i < len(stops) - 2:
                d += f" L{xb:.1f},{next_out:.1f}"
        # Label on the first curve, near its end with more neighbours: where a fan's edges are still apart.
        (_, out_y, xa), (in_y, _, xb) = stops[0], stops[1]
        room = (_pill_height(link.kinds) / 2 + 6) / (in_y - out_y)
        if fan_in[link.target] > fan_out[link.source]:
            f = max(0.16, room)
        elif fan_out[link.source] > fan_in[link.target]:
            f = 1 - max(0.16, room)
        else:
            f = 0.5
        # A point of the S-curve: x and y follow the same Bezier weights, so (f, f) stays on it.
        pills.append(Pill(layout.layer[link.source], xa + (xb - xa) * f, out_y + (in_y - out_y) * f, link.kinds))
        edges += [_stroke(d, color), _arrow(x2, y2 - R, "down", color)]
    return Drawing(pos, edges, pills, right, y)


def _stroke(d: str, color: str) -> str:
    return f'<path d="{d}" fill="none" stroke="{color}" stroke-width="2"/>'


def _pill_width(kinds: list[str]) -> float:
    return max(_text_width(k, LABEL_FS, True) for k in kinds) + 14


def _pill_height(kinds: list[str]) -> float:
    return (LABEL_FS + 5) * len(kinds) + 6


def _spread(pills: list[Pill], *, horizontal: bool = False) -> list[tuple[float, float, list[str]]]:
    """Push apart labels that would overlap within the same gap (sideways when the gap is horizontal)."""
    out = []
    for gap in sorted({p.gap for p in pills}):
        if horizontal and gap >= 0:
            row = sorted((p for p in pills if p.gap == gap), key=lambda p: p.x)
            edge = float("-inf")
            for _, x, y, kinds in row:
                half = _pill_width(kinds) / 2
                x = max(x, edge + half + 6)
                edge = x + half
                out.append((x, y, kinds))
            continue
        column = sorted((p for p in pills if p.gap == gap), key=lambda p: p.y)
        bottom = float("-inf")
        for _, x, y, kinds in column:
            half = _pill_height(kinds) / 2
            y = max(y, bottom + half + 4)
            bottom = y + half
            out.append((x, y, kinds))
    return out


def _arrow(x: float, y: float, direction: str, color: str) -> str:
    dx, dy = {"right": (-11, 0), "left": (11, 0), "down": (0, -11), "up": (0, 11)}[direction]
    if dx:
        points = f"{x:.1f},{y:.1f} {x + dx:.1f},{y - 6:.1f} {x + dx:.1f},{y + 6:.1f}"
    else:
        points = f"{x:.1f},{y:.1f} {x - 6:.1f},{y + dy:.1f} {x + 6:.1f},{y + dy:.1f}"
    return f'<polygon points="{points}" fill="{color}"/>'


def _pill(x: float, y: float, kinds: list[str]) -> list[str]:
    line_h = LABEL_FS + 5
    w = _pill_width(kinds)
    h = _pill_height(kinds)
    top = y - h / 2
    rect = (f'<rect x="{x - w / 2:.1f}" y="{top:.1f}" width="{w:.1f}" height="{h:.1f}" rx="{min(h / 2, 11):.1f}" '
            'fill="#ffffff" stroke="#d5dbe1"/>')
    out = [rect]
    for i, kind in enumerate(kinds):
        color = SEVERITY_COLOR.get(severity(kind), MUTED)
        out.append(_text(x, top + 3 + line_h * (i + 1) - 5, kind, LABEL_FS, color, anchor="middle", bold=True))
    return out


def _node(node: Node, xy: tuple[float, float], label: tuple[str, str], waypoint: bool) -> str:
    x, y = xy
    color = KIND_COLOR.get(node.kind, "#78909c")
    out = []
    if waypoint:
        out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{R + 8}" fill="none" stroke="{INK}" '
                   'stroke-width="1.5" stroke-dasharray="4 3"/>')
    ring = f' stroke="{T0_COLOR}" stroke-width="4"' if node.tier_zero else ' stroke="#ffffff" stroke-width="2"'
    out.append(f'<circle cx="{x:.1f}" cy="{y:.1f}" r="{R}" fill="{color}"{ring}/>')
    out.append(_icon(node.kind, x, y))
    out.append(_text(x, y + R + 20, label[0], 13, INK, anchor="middle", bold=True))
    if label[1]:
        out.append(_text(x, y + R + 35, label[1], 11, MUTED, anchor="middle"))
    badges = [("T0", T0_COLOR)] if node.tier_zero else []
    if node.owned:
        badges.append(("OWNED", OWNED_COLOR))
    if node.properties.get("enabled") is False:
        badges.append(("DISABLED", MUTED))
    bx = x + R * 0.55
    for text, badge_color in badges:
        w = _text_width(text, 10, True) + 10
        out.append(f'<rect x="{bx:.1f}" y="{y - R - 8:.1f}" width="{w:.1f}" height="16" rx="8" fill="{badge_color}"/>')
        out.append(_text(bx + w / 2, y - R + 4, text, 10, "#ffffff", anchor="middle", bold=True))
        bx += w + 3
    if waypoint:
        out.append(_text(x - R - 4, y - R - 2, "via", 10, INK, anchor="end", bold=True))
    return "\n".join(out)


def _icon(kind: str, x: float, y: float) -> str:
    """A small white glyph for the object kind, drawn with basic shapes."""
    w = 'fill="#ffffff"'
    if kind == "User":
        return (f'<circle cx="{x:.1f}" cy="{y - 5:.1f}" r="6" {w}/>'
                f'<path d="M{x - 11:.1f},{y + 12:.1f} Q{x:.1f},{y - 4:.1f} {x + 11:.1f},{y + 12:.1f} Z" {w}/>')
    if kind == "Group":
        out = []
        for dx, r in ((-6, 5), (7, 5)):
            out.append(f'<circle cx="{x + dx:.1f}" cy="{y - 5:.1f}" r="{r}" {w}/>')
            out.append(f'<path d="M{x + dx - 9:.1f},{y + 11:.1f} Q{x + dx:.1f},{y - 3:.1f} {x + dx + 9:.1f},'
                       f'{y + 11:.1f} Z" {w}/>')
        return "".join(out)
    if kind == "Computer":
        return (f'<rect x="{x - 12:.1f}" y="{y - 10:.1f}" width="24" height="15" rx="2" {w}/>'
                f'<rect x="{x - 3:.1f}" y="{y + 5:.1f}" width="6" height="4" {w}/>'
                f'<rect x="{x - 8:.1f}" y="{y + 9:.1f}" width="16" height="3" rx="1" {w}/>')
    if kind == "Domain":
        stroke = 'fill="none" stroke="#ffffff" stroke-width="2"'
        return (f'<circle cx="{x:.1f}" cy="{y:.1f}" r="12" {stroke}/>'
                f'<ellipse cx="{x:.1f}" cy="{y:.1f}" rx="5" ry="12" {stroke}/>'
                f'<line x1="{x - 12:.1f}" y1="{y:.1f}" x2="{x + 12:.1f}" y2="{y:.1f}" stroke="#ffffff" '
                'stroke-width="2"/>')
    if kind == "OU" or kind == "Container":
        return (f'<path d="M{x - 12:.1f},{y - 8:.1f} h8 l3,3 h13 v15 h-24 Z" {w}/>')
    if kind == "GPO":
        return (f'<path d="M{x - 9:.1f},{y - 12:.1f} h12 l6,6 v18 h-18 Z" {w}/>'
                f'<line x1="{x - 5:.1f}" y1="{y + 1:.1f}" x2="{x + 5:.1f}" y2="{y + 1:.1f}" '
                f'stroke="{KIND_COLOR["GPO"]}" stroke-width="2"/>')
    return _text(x, y + 5, kind[:2].upper(), 13, "#ffffff", anchor="middle", bold=True)


def _legend(x: float, y: float, layout: Layout, waypoints: bool,
            max_width: float = float("inf")) -> tuple[list[str], float, float]:
    """Legend entries for what the diagram shows, wrapped at `max_width`; returns (elements, width, height)."""
    items: list[tuple[str, str]] = []  # (marker drawn in a 18px box at `mx`, caption)
    for kind, color in KIND_COLOR.items():
        if any(n.kind == kind for n in layout.nodes.values()):
            items.append((f'<circle cx="{{mx}}" cy="{{cy}}" r="6" fill="{color}"/>', kind))
    present = {severity(k) for link in layout.links.values() for k in link.kinds}
    for level, color in SEVERITY_COLOR.items():
        if level in present:
            line = (f'<line x1="{{mx_l}}" y1="{{cy}}" x2="{{mx_r}}" y2="{{cy}}" stroke="{color}" '
                    'stroke-width="2.5"/>')
            items.append((line, f"{level} edge"))
    if any(n.tier_zero for n in layout.nodes.values()):
        ring = f'<circle cx="{{mx}}" cy="{{cy}}" r="6" fill="#ffffff" stroke="{T0_COLOR}" stroke-width="2.5"/>'
        items.append((ring, "Tier Zero"))
    if waypoints:
        dashed = f'<circle cx="{{mx}}" cy="{{cy}}" r="6" fill="none" stroke="{INK}" stroke-dasharray="3 2"/>'
        items.append((dashed, "waypoint (--via)"))
    out, start, widest, lines = [], x, 0.0, 1
    for marker, caption in items:
        step = 24 + _text_width(caption, 11) + 20
        if x > start and x + step - 20 - start > max_width:
            x, y, lines = start, y + 20, lines + 1
        out.append(marker.format(mx=f"{x + 9:.1f}", mx_l=f"{x:.1f}", mx_r=f"{x + 18:.1f}", cy=f"{y - 4:.1f}"))
        out.append(_text(x + 24, y, caption, 11, MUTED))
        x += step
        widest = max(widest, x - 20 - start)
    return out, widest, 20.0 * lines


def _text(x: float, y: float, text: str, size: float, color: str, *, anchor: str = "start",
          bold: bool = False) -> str:
    weight = ' font-weight="bold"' if bold else ""
    return (f'<text x="{x:.1f}" y="{y:.1f}" font-family={quoteattr(FONT)} font-size="{size}" fill="{color}" '
            f'text-anchor="{anchor}"{weight}>{escape(text)}</text>')


def _document(width: float, height: float, parts: list[str]) -> str:
    return (f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
            f'viewBox="0 0 {width:.0f} {height:.0f}">\n'
            f'<rect width="100%" height="100%" fill="#ffffff"/>\n' + "\n".join(parts) + "\n</svg>\n")
