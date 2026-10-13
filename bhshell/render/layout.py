"""Layered layout shared by the path graph renderers.

Paths are merged into one graph where every object appears once. Objects are placed in
layers by hop distance (longest path from a start), a link skipping layers is routed
through a virtual point in each layer it crosses, and each layer is ordered with
barycenter sweeps to limit crossings. Links that close a cycle (a route revisiting an
object) are flagged `back` and left out of the layering.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass, field

from bhshell.models.entities import Node
from bhshell.queries.paths import AttackPath


def split_name(node: Node) -> tuple[str, str]:
    """`JDOE@CORP.LOCAL` -> (`JDOE`, `CORP.LOCAL`); `WS01.CORP.LOCAL` -> (`WS01`, `CORP.LOCAL`)."""
    name = node.name
    if "@" in name:
        head, _, tail = name.partition("@")
        return head, tail
    if node.kind == "Computer" and "." in name:
        head, _, tail = name.partition(".")
        return head, tail
    return name, ""


@dataclass
class Link:
    source: str
    target: str
    kinds: list[str] = field(default_factory=list)
    back: bool = False
    # Keys from source to target, with a virtual point in every column the link crosses.
    lane: list[str] = field(default_factory=list)


class Layout:
    """Layered (Sugiyama-style) layout: columns by hop distance, long links routed through virtual points."""

    def __init__(self, paths: list[AttackPath]) -> None:
        self.nodes: dict[str, Node] = {}
        self.links: dict[tuple[str, str], Link] = {}
        for path in paths:
            for hop in path.hops:
                a, b = self._add(hop.source), self._add(hop.target)
                link = self.links.setdefault((a, b), Link(a, b))
                if hop.edge not in link.kinds:
                    link.kinds.append(hop.edge)
        self.starts = list(dict.fromkeys(self._key(p.start) for p in paths))
        self._mark_back_links()
        self.layer = self._layers()
        self.virtual: set[str] = set()
        self._add_lanes()
        self.columns = self._order()

    @staticmethod
    def _key(node: Node) -> str:
        return node.objectid or node.name

    def _add(self, node: Node) -> str:
        key = self._key(node)
        self.nodes.setdefault(key, node)
        return key

    def _successors(self, key: str) -> list[Link]:
        return [link for link in self.links.values() if link.source == key and not link.back]

    def _mark_back_links(self) -> None:
        """Flag links closing a cycle (possible when a route revisits an object) so layering stays acyclic."""
        state: dict[str, int] = {}  # 1 = on the DFS stack, 2 = done
        for start in [*self.starts, *self.nodes]:
            if start in state:
                continue
            stack = [(start, iter(self._successors(start)))]
            state[start] = 1
            while stack:
                node, links = stack[-1]
                link = next(links, None)
                if link is None:
                    state[node] = 2
                    stack.pop()
                elif state.get(link.target) == 1:
                    link.back = True
                elif link.target not in state:
                    state[link.target] = 1
                    stack.append((link.target, iter(self._successors(link.target))))

    def _layers(self) -> dict[str, int]:
        """Longest-path layering: an object sits one column right of its furthest predecessor."""
        layer = dict.fromkeys(self.nodes, 0)
        for _ in range(len(self.nodes)):
            changed = False
            for link in self.links.values():
                if not link.back and layer[link.target] < layer[link.source] + 1:
                    layer[link.target] = layer[link.source] + 1
                    changed = True
            if not changed:
                break
        return layer

    def _add_lanes(self) -> None:
        for i, link in enumerate(self.links.values()):
            if link.back:
                link.lane = [link.source, link.target]
                continue
            points = [f"~{i}.{col}" for col in range(self.layer[link.source] + 1, self.layer[link.target])]
            for point, col in zip(points, range(self.layer[link.source] + 1, self.layer[link.target]), strict=True):
                self.layer[point] = col
                self.virtual.add(point)
            link.lane = [link.source, *points, link.target]

    def _order(self) -> list[list[str]]:
        """Columns of keys, ordered with a few barycenter sweeps to limit crossings."""
        columns: list[list[str]] = [[] for _ in range(max(self.layer.values(), default=0) + 1)]
        for key in self.layer:  # insertion order follows the (sorted) paths
            columns[self.layer[key]].append(key)
        steps = [pair for link in self.links.values() if not link.back for pair in itertools.pairwise(link.lane)]
        for _ in range(6):
            for i in range(1, len(columns)):
                self._sort_by_neighbours(columns[i], columns[i - 1], [(b, a) for a, b in steps])
            for i in range(len(columns) - 2, -1, -1):
                self._sort_by_neighbours(columns[i], columns[i + 1], steps)
        return columns

    @staticmethod
    def _sort_by_neighbours(column: list[str], fixed: list[str], pairs: list[tuple[str, str]]) -> None:
        position = {key: i for i, key in enumerate(fixed)}
        current = {key: i for i, key in enumerate(column)}

        def barycenter(key: str) -> float:
            seen = [position[other] for node, other in pairs if node == key and other in position]
            return sum(seen) / len(seen) if seen else current[key]

        column.sort(key=barycenter)
