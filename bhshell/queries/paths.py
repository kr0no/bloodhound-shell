"""Attack-path finding.

* `shortest(src, dst)` uses BH's native `GET /api/v2/graphs/shortest-path`
  (BloodHound's own traversable-edge rules) and falls back to Cypher.
* Everything else, and `shortest` with excluded edges, uses Cypher `allShortestPaths`.
* `route(src, waypoints, dst)` chains one of the above per leg.

A disabled user or computer can only be passed through when the hop reaching it grants the
right to re-enable it (`ENABLE_EDGES`), unless `include_disabled` is set. BloodHound's Cypher
cannot express that rule (it rejects `endNode(r).enabled`), so each Cypher search runs twice:
unfiltered, and avoiding disabled objects altogether (so a longer path around them is still
found). `_build` applies the exact rule to the union, and to REST results too.

Every API returns the union of the paths as one subgraph; `Graph.paths` splits it back into
individual chains.
"""

from __future__ import annotations

import itertools
import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from typing import Any, Literal

from bhshell.client.client import route_missing
from bhshell.errors import ApiError, CypherDisabledError, NotFoundError, UnsupportedFeature
from bhshell.models.entities import OWNED_LABEL, TIER_ZERO_LABEL, Edge, Graph, Node
from bhshell.models.results import Backend
from bhshell.queries import cypher as Q
from bhshell.queries.edges import ENABLE_EDGES, HAS_SESSION, PASSIVE_EDGES, TRAVERSABLE_EDGES, severity
from bhshell.queries.service import RAISE_LIMIT, EntityService, truncation_note


@dataclass
class Hop:
    source: Node
    edge: str
    target: Node


@dataclass
class AttackPath:
    hops: list[Hop]

    @property
    def start(self) -> Node:
        return self.hops[0].source

    @property
    def end(self) -> Node:
        return self.hops[-1].target

    def __len__(self) -> int:
        return len(self.hops)

    @property
    def actions(self) -> int:
        """Hops the operator has to act on (group membership, containment and GPO links come for free)."""
        return sum(h.edge not in PASSIVE_EDGES for h in self.hops)

    def as_dict(self) -> dict[str, Any]:
        return {
            "start": self.start.name,
            "end": self.end.name,
            "length": len(self),
            "actions": self.actions,
            "hops": [{"source": h.source.name, "edge": h.edge, "target": h.target.name,
                      "target_kind": h.target.kind, "tier_zero": h.target.tier_zero} for h in self.hops],
        }


@dataclass
class PathResult:
    title: str
    paths: list[AttackPath] = field(default_factory=list)
    # "mixed" when the legs of a route came from different backends.
    backend: Backend | Literal["mixed"] = "cypher"
    notes: list[str] = field(default_factory=list)
    # Object IDs of the --via steps of a route.
    waypoints: list[str] = field(default_factory=list)
    # Numbers shown next to the paths, when they are a pick from a longer list (default 1, 2, ...).
    numbers: list[int] = field(default_factory=list)
    # Disabled objects whose paths were skipped: they are reached without a right to re-enable them.
    skipped_disabled: list[str] = field(default_factory=list)

    @property
    def shortest(self) -> int:
        return min((len(p) for p in self.paths), default=0)

    def first_hops(self) -> set[tuple[str, str, str]]:
        return {(p.start.name, p.hops[0].edge, p.hops[0].target.name) for p in self.paths}

    def as_dict(self) -> dict[str, Any]:
        return {"title": self.title, "backend": self.backend, "notes": self.notes,
                "skipped_disabled": self.skipped_disabled, "paths": [p.as_dict() for p in self.paths]}

    def rows(self) -> list[dict[str, Any]]:
        """Flattened rows for CSV export."""
        return [
            {"path": i, "hop": j, "source": h.source.name, "edge": h.edge, "target": h.target.name,
             "target_kind": h.target.kind, "tier_zero": h.target.tier_zero}
            for i, p in enumerate(self.paths, 1) for j, h in enumerate(p.hops, 1)
        ]


def _var_length(edges: frozenset[str] | None) -> str:
    return f"[:{Q.edge_types(edges)}*1..]" if edges else "[*1..]"


def _no_disabled(*keep: str) -> str:
    """Cypher condition: path `p` crosses no disabled object, except its start `s` and the `keep` endpoints
    (aliases) the user named.

    Stricter than the rule `_build` applies (a disabled object reached with a right to re-enable it is
    fine), so it is only used alongside an unfiltered search.
    """
    exempt = "".join(f" OR n = {alias}" for alias in ("s", *keep))
    return f"all(n IN nodes(p) WHERE n.enabled IS NULL OR n.enabled = true{exempt})"


# Builds a path query from a relationship pattern and whether to exclude disabled objects.
QueryBuilder = Callable[[str, bool], str]


class PathService:
    def __init__(self, entities: EntityService, *, include_disabled: bool = False,
                 exclude: Iterable[str] = ()) -> None:
        self.entities = entities
        self.client = entities.client
        self.include_disabled = include_disabled
        # Edge kinds the paths may not use (techniques the operator cannot or will not use).
        self.exclude = frozenset(exclude)
        self.edges = TRAVERSABLE_EDGES - self.exclude

    def shortest(self, src: Node, dst: Node) -> PathResult:
        result = PathResult(f"Shortest path: {src.name} → {dst.name}")
        if self.exclude:  # the native pathfinder cannot leave edges out
            return self._build(result, self._cypher_shortest(src, dst, result), [src.objectid],
                               lambda n: n.objectid == dst.objectid, keep=[dst.objectid])
        try:
            resp = self.client.get("api/v2/graphs/shortest-path", start_node=src.objectid, end_node=dst.objectid)
            graph = Graph.from_cypher((resp or {}).get("data") or {})
            result.backend = "rest"
        except NotFoundError as exc:
            if not route_missing(exc):
                return result  # "path not found": a valid, empty answer
            return self._build(result, self._cypher_shortest(src, dst, result), [src.objectid],
                               lambda n: n.objectid == dst.objectid, keep=[dst.objectid])
        self._build(result, graph, [src.objectid], lambda n: n.objectid == dst.objectid, keep=[dst.objectid])
        if not result.paths and result.skipped_disabled and self.entities.cypher_available is not False:
            # Every native shortest path crosses a disabled object: look for one around them.
            # The retry notes its own skipped objects; one note then lists both searches'.
            skipped = _skipped_note(result.skipped_disabled)
            retry = PathResult(result.title, backend="cypher", notes=[n for n in result.notes if n != skipped])
            retry.notes.append("The shortest paths cross disabled objects; showing paths around them.")
            try:
                graph = self._cypher_shortest(src, dst, retry)
            except (ApiError, UnsupportedFeature):
                return result
            self._build(retry, graph, [src.objectid], lambda n: n.objectid == dst.objectid, keep=[dst.objectid])
            retry.notes = [n for n in retry.notes if n != _skipped_note(retry.skipped_disabled)]
            retry.skipped_disabled = sorted({*result.skipped_disabled, *retry.skipped_disabled})
            retry.notes.append(_skipped_note(retry.skipped_disabled))
            return retry
        return result

    def _cypher_shortest(self, src: Node, dst: Node, result: PathResult) -> Graph:
        ends = (f"s.objectid = {Q.lit(src.objectid)}", f"t.objectid = {Q.lit(dst.objectid)}")
        limit = self.entities.max_results
        return self._first_working(lambda rel, filtered: (
            f"MATCH p=allShortestPaths((s:Base)-{rel}->(t:Base))"
            f"{Q.where(*ends, _no_disabled('t') if filtered else '')} RETURN p LIMIT {limit}"
        ), result)

    def to_tier_zero(self, src: Node) -> PathResult:
        result = PathResult(f"Shortest paths: {src.name} → Tier Zero")
        if src.tier_zero:
            result.notes.append(f"{src.name} is already Tier Zero.")
            return result
        graph = self._shortest_to_tier_zero("(s:Base)", f"s.objectid = {Q.lit(src.objectid)}", result)
        return self._build(result, graph, [src.objectid], lambda n: n.tier_zero and n.objectid != src.objectid)

    def route(self, src: Node, waypoints: list[Node], dst: Node | None) -> PathResult:
        """Paths from `src` through each waypoint in order, then to `dst` (Tier Zero when `None`).

        Every leg is a separate shortest-path search and the legs' paths are chained, so a route
        is shortest between consecutive steps but not necessarily the shortest overall.
        """
        steps = [src, *waypoints]
        result = PathResult("Shortest route: " + " → ".join(
            [n.name for n in steps] + [dst.name if dst else "Tier Zero"]))
        result.waypoints = [n.objectid for n in waypoints]
        legs: list[PathResult] = []
        for a, b in zip(steps, [*waypoints, dst], strict=True):
            target = b.name if b else "Tier Zero"
            if b is None and a.tier_zero:
                result.notes.append(f"{a.name} is already Tier Zero; the route ends there.")
                break
            leg = self.shortest(a, b) if b else self.to_tier_zero(a)
            result.notes += [f"{a.name} → {target}: {note}" for note in leg.notes]
            if not leg.paths:
                result.notes.append(f"No path from {a.name} to {target}.")
                return result
            legs.append(leg)

        limit = self.entities.max_results
        combos = itertools.islice(itertools.product(*(leg.paths for leg in legs)), limit)
        result.paths = sorted((AttackPath([h for p in combo for h in p.hops]) for combo in combos), key=_rank)
        total = math.prod(len(leg.paths) for leg in legs)
        if total > limit:
            result.notes.append(f"Only {limit} of {total:,} leg combinations are listed ({RAISE_LIMIT}).")
        backends = {leg.backend for leg in legs}
        result.backend = backends.pop() if len(backends) == 1 else "mixed"
        return result

    def owned_to_tier_zero(self) -> PathResult:
        result = PathResult("Shortest paths: owned objects → Tier Zero")
        graph = self._shortest_to_tier_zero(f"(s:{OWNED_LABEL})", "", result)
        # Paths stop at the first Tier Zero object, so owned Tier Zero objects never start one: ask for them.
        tier_zero = self._cypher(f"MATCH (n:{OWNED_LABEL}) WHERE n:{TIER_ZERO_LABEL} RETURN n")
        already = sorted(n.name for n in tier_zero.nodes.values())
        if already:
            result.notes.append("Owned objects that are already Tier Zero: " + ", ".join(already))
        if not any(n.owned and not n.tier_zero for n in graph.nodes.values()):
            result.notes.append("No other owned object has a path to Tier Zero." if already else
                                "No owned object has a path to Tier Zero (or nothing is marked owned).")
        return self._build(result, graph, None, lambda n: n.tier_zero)

    def reaching_tier_zero(self, objectids: Iterable[str]) -> tuple[set[str], list[str]]:
        """Which of `objectids` have a path to Tier Zero, and notes about the search."""
        ids = sorted(set(objectids))
        if not ids:
            return set(), []
        result = PathResult("")
        cond = f"s.objectid IN [{', '.join(Q.lit(i) for i in ids)}]"
        graph = self._shortest_to_tier_zero("(s:Base)", cond, result)
        # Split into paths as `path` does, so disabled objects and a cut-off result count the same way.
        self._build(result, graph, ids, lambda n: n.tier_zero)
        skipped = _skipped_note(result.skipped_disabled) if result.skipped_disabled else None
        return {p.start.objectid for p in result.paths}, [n for n in result.notes if n != skipped]

    def owned_to(self, dst: Node) -> PathResult:
        """Shortest paths from every owned object to `dst` (an objective other than Tier Zero)."""
        result = PathResult(f"Shortest paths: owned objects → {dst.name}")
        if dst.owned:
            result.notes.append(f"{dst.name} is already owned.")
            return result
        limit = self.entities.max_results
        graph = self._first_working(lambda rel, filtered: (
            f"MATCH p=allShortestPaths((s:{OWNED_LABEL})-{rel}->(t:Base))"
            f"{Q.where('s <> t', f't.objectid = {Q.lit(dst.objectid)}', _no_disabled('t') if filtered else '')} "
            f"RETURN p LIMIT {limit}"
        ), result)
        sources = [n.objectid for n in graph.nodes.values() if n.owned]
        if not sources:
            result.notes.append(f"No owned object has a path to {dst.name} (or nothing is marked owned).")
        return self._build(result, graph, sources, lambda n: n.objectid == dst.objectid, keep=[dst.objectid])

    def _shortest_to_tier_zero(self, s_match: str, s_cond: str, result: PathResult) -> Graph:
        """allShortestPaths from the `s` nodes matched by `s_match` and `s_cond` to Tier Zero.

        Paths stop at the first Tier Zero object: the ones going on through it (domain -> every
        Tier Zero object it contains) are cut there anyway, and would fill the LIMIT.
        """
        limit = self.entities.max_results

        def search(stop: str) -> Graph:
            return self._first_working(lambda rel, filtered: (
                f"MATCH p=allShortestPaths({s_match}-{rel}->(t:{TIER_ZERO_LABEL}))"
                f"{Q.where('s <> t', s_cond, stop, _no_disabled() if filtered else '')} RETURN p LIMIT {limit}"
            ), result)

        try:
            return search(f"all(n IN nodes(p) WHERE n = t OR NOT n:{TIER_ZERO_LABEL})")
        except ApiError:
            return search("")

    def _first_working(self, build: QueryBuilder, result: PathResult) -> Graph:
        """Run with the traversable-edge filter, dropping it if the server rejects it."""
        try:
            return self._search(build, self.edges, result)
        except ApiError:
            graph = self._search(build, None, result)
            result.notes.append("Server rejected the traversable-edge filter; paths may include "
                                "non-traversable edges.")
            return graph

    def _search(self, build: QueryBuilder, edges: frozenset[str] | None, result: PathResult) -> Graph:
        """The unfiltered search, merged (unless disabled objects are allowed) with one avoiding them."""
        rel = _var_length(edges)
        graph = self._cypher(build(rel, False))
        if self.include_disabled:
            return graph
        try:
            around = self._cypher(build(rel, True))
        except ApiError:
            result.notes.append("Server rejected the disabled-object filter; some longer paths around "
                                "disabled objects may be missing.")
            return graph
        merged = Graph.union([graph, around])
        merged.query = graph.query  # for the truncation check
        return merged

    def _cypher(self, query: str) -> Graph:
        try:
            return self.entities.run_cypher(query)
        except CypherDisabledError as exc:
            raise UnsupportedFeature("Path finding needs the Cypher endpoint") from exc

    def _disabled(self, graph: Graph, result: PathResult) -> set[str]:
        """Node IDs of disabled objects in `graph`, looking up those whose result lacks properties (REST)."""
        disabled = {nid for nid, n in graph.nodes.items() if n.properties.get("enabled") is False}
        unknown = sorted({n.objectid for n in graph.nodes.values()
                          if n.objectid and "enabled" not in n.properties and n.kind in ("User", "Computer")})
        if not unknown or self.entities.cypher_available is False:
            return disabled
        ids = ", ".join(Q.lit(o) for o in unknown)
        try:
            found = self.entities.run_cypher(
                f"MATCH (n:Base) WHERE n.objectid IN [{ids}] AND n.enabled = false RETURN n")
        except (ApiError, CypherDisabledError):
            result.notes.append("Could not check which objects on the paths are disabled.")
            return disabled
        oids = {n.objectid for n in found.nodes.values()}
        for nid, n in graph.nodes.items():
            if n.objectid in oids:
                n.properties["enabled"] = False  # REST nodes carry no properties; lets renderers mark them
                disabled.add(nid)
        return disabled

    def _build(self, result: PathResult, graph: Graph, source_oids: list[str] | None,
               is_target: Callable[[Node], bool], *, keep: Iterable[str] = ()) -> PathResult:
        """Split `graph` into paths from `source_oids` (`None`: every owned, non-Tier-Zero object).

        Sources and the `keep` object IDs are never skipped as disabled: the user chose them.
        """
        full = graph
        if self.exclude:  # in case the server rejected the edge filter
            graph = Graph(dict(graph.nodes), [e for e in graph.edges if e.kind not in self.exclude])
        by_oid = {n.objectid: nid for nid, n in graph.nodes.items()}
        if source_oids is None:
            sources = [nid for nid, n in graph.nodes.items() if n.owned and not n.tier_zero]
        else:
            sources = [by_oid[o] for o in source_oids if o in by_oid]
        limit = self.entities.max_results
        if not self.include_disabled:
            exempt = {by_oid[o] for o in keep if o in by_oid} | set(sources)
            disabled = self._disabled(graph, result) - exempt

            def blocked(e: Edge) -> bool:
                return e.target in disabled and e.kind not in ENABLE_EDGES

            if any(blocked(e) for e in graph.edges):
                full_targets = [nid for nid, n in graph.nodes.items() if is_target(n)]
                hit = {e.target for chain in graph.paths(sources, full_targets, max_paths=limit)
                       for e in chain if blocked(e)}
                result.skipped_disabled = sorted(graph.nodes[nid].name for nid in hit)
                graph = Graph(dict(graph.nodes), [e for e in graph.edges if not blocked(e)])
            if result.skipped_disabled:
                result.notes.append(_skipped_note(result.skipped_disabled))
        targets = [nid for nid, n in graph.nodes.items() if is_target(n)]
        chains = graph.paths(sources, targets, max_paths=limit)
        result.paths = [self._to_path(graph, chain) for chain in chains]
        result.paths.sort(key=_rank)
        truncated, total = self.entities.truncation(full)
        if truncated or len(chains) >= limit:
            result.notes.append(truncation_note(limit, [total if truncated else None]))
        return result

    @staticmethod
    def _to_path(graph: Graph, chain: list[Edge]) -> AttackPath:
        return AttackPath([Hop(graph.nodes[e.source], e.kind, graph.nodes[e.target]) for e in chain])


def _skipped_note(names: list[str]) -> str:
    return (f"Skipped paths through {len(names)} disabled object(s) reached without a right to re-enable them: "
            f"{', '.join(names)} (--include-disabled shows them).")


def _rank(path: AttackPath) -> tuple[int, int, int, int, str, str]:
    """Fewest actions first (each one is a chance to be detected), then the fewest hops relying on a
    session (a snapshot that may be gone), the shortest, and the fewest non-critical hops."""
    sessions = sum(h.edge == HAS_SESSION for h in path.hops)
    risk = sum(severity(h.edge) != "critical" for h in path.hops)
    return path.actions, sessions, len(path), risk, path.start.name, path.end.name
