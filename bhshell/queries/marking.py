"""Owned / Tier Zero (high value) marking.

Listing matches the `Tag_Owned` / `Tag_Tier_Zero` kinds in Cypher. Marking adds or removes
selectors through the privilege-zone API (`/api/v2/asset-group-tags`).
"""

from __future__ import annotations

from typing import Any, Literal

from bhshell.client.client import BHClient
from bhshell.errors import ApiError, BHError, CypherDisabledError, NotFoundError, UnsupportedFeature
from bhshell.models.entities import OWNED_LABEL, TIER_ZERO_LABEL, Node
from bhshell.queries.service import EntityService

Tag = Literal["owned", "tier0"]

_KIND_LABEL = {"owned": OWNED_LABEL, "tier0": TIER_ZERO_LABEL}
_TAG_TYPE = {"owned": 3, "tier0": 1}
_TAG_NAME = {"owned": "Owned", "tier0": "Tier Zero"}
_SEED_OBJECT_ID = 1
_SELECTOR_PREFIX = "bhshell: "


class MarkingService:
    def __init__(self, client: BHClient, entities: EntityService) -> None:
        self.client = client
        self.entities = entities

    def list(self, tag: Tag) -> list[Node]:
        try:
            graph = self.entities.run_cypher(f"MATCH (n:{_KIND_LABEL[tag]}) RETURN n")
        except CypherDisabledError as exc:
            raise UnsupportedFeature("Listing tagged objects needs the Cypher endpoint") from exc
        return sorted(graph.nodes.values(), key=lambda n: (n.kind, n.name))

    def mark(self, node: Node, tag_obj: dict[str, Any], *, add: bool = True) -> str:
        """Add or remove `node` from a tag returned by `tag`. Returns a human-readable status."""
        if add:
            return self._add(node, tag_obj)
        return self._remove(node, tag_obj)

    def tag(self, tag: Tag) -> dict[str, Any]:
        """The Owned label, or the Tier Zero tier (the tier with the lowest position)."""
        try:
            resp = self.client.get("api/v2/asset-group-tags") or {}
        except NotFoundError as exc:
            raise UnsupportedFeature("This BH version has no asset-group tags API") from exc
        tags = (resp.get("data") or {}).get("tags") or []
        candidates = sorted((t for t in tags if t.get("type") == _TAG_TYPE[tag]),
                            key=lambda t: t.get("position") or 0)
        if not candidates:
            raise NotFoundError(f"The server has no {_TAG_NAME[tag]} tag")
        return candidates[0]

    def _add(self, node: Node, tag_obj: dict[str, Any]) -> str:
        base = f"api/v2/asset-group-tags/{tag_obj['id']}/selectors"
        tag_name = tag_obj.get("name")
        if _tagged(node, tag_obj):
            return f"{node.name} is already in '{tag_name}'; nothing to add."
        existing = self._selecting(base, node)
        if existing:
            names = ", ".join(_selector_name(s) for s in existing)
            return f"{node.name} is already in '{tag_name}' (selector: {names}); nothing to add."
        body = {
            "name": f"{_SELECTOR_PREFIX}{node.name}",
            "description": "Created by bhshell",
            "seeds": [{"type": _SEED_OBJECT_ID, "value": node.objectid}],
        }
        try:
            self.client.request("POST", base, json_body=body)
        except ApiError as exc:
            if exc.status != 409:
                raise
            raise BHError(f"A selector named '{body['name']}' already exists in '{tag_name}' but does not target "
                          f"{node.name}", hint="Rename or delete it in the BH UI, then retry.") from exc
        return f"Added {node.name} to '{tag_name}' (selector created; applied after analysis)."

    def _selecting(self, base: str, node: Node) -> list[dict[str, Any]]:
        """Every selector of the tag seeded with `node` (listed in full: callers may delete while iterating)."""
        return [s for s in self.client.paginate(base)
                if node.objectid in [seed.get("value") for seed in s.get("seeds") or []]]

    def _selected_by(self, tag_obj: dict[str, Any], node: Node) -> list[Any] | None:
        """IDs of the selectors that put `node` in the tag at the last analysis (`None` if unknown)."""
        if not node.id.isdigit():  # not a graph ID (REST lookup)
            return None
        try:
            resp = self.client.get(f"api/v2/asset-group-tags/{tag_obj['id']}/members/{node.id}")
        except (NotFoundError, ApiError):
            return None
        return _member_selectors(resp)

    def _remove(self, node: Node, tag_obj: dict[str, Any]) -> str:
        """Delete the selectors seeded with this object alone.

        A selector that also seeds other objects is left intact so they stay marked.
        """
        base = f"api/v2/asset-group-tags/{tag_obj['id']}/selectors"
        removed, shared = 0, []
        # Listed in full first: deleting while paginating would shift the offsets and skip selectors.
        for selector in self._selecting(base, node):
            if all(s.get("value") == node.objectid for s in selector.get("seeds") or []):
                self.client.request("DELETE", f"{base}/{selector['id']}")
                removed += 1
            else:
                shared.append(_selector_name(selector))
        tag_name = tag_obj.get("name")
        if not removed:
            if shared:
                raise BHError(f"{node.name} is only selected by selectors that also cover other objects: "
                              f"{', '.join(shared)}",
                              hint="Edit those selectors in the BH UI to unmark just this object.")
            if _tagged(node, tag_obj):
                current = {s.get("id"): s for s in self.client.paginate(base)}
                selected_by = self._selected_by(tag_obj, node)
                if selected_by is None:  # no member endpoint: any rule-based selector may be the one
                    rules = [_selector_name(s) for s in current.values()
                             if any(seed.get("type") != _SEED_OBJECT_ID for seed in s.get("seeds") or [])]
                else:  # as of the last analysis; a selector deleted since then no longer counts
                    rules = [_selector_name(current[i]) for i in selected_by if i in current]
                if not rules:  # its own selector is gone: the tag stays until the next analysis
                    return (f"No selector in '{tag_name}' targets {node.name} any more; it stays tagged until "
                            "BloodHound's next analysis.")
                raise BHError(f"{node.name} is in '{tag_name}' through a rule-based selector, not one naming it: "
                              f"{', '.join(rules)}",
                              hint="Change that selector in the BH UI (Privilege Zones) to unmark it.")
            raise NotFoundError(f"No selector in '{tag_name}' targets {node.name}")
        message = f"Removed {removed} selector(s) for {node.name} from '{tag_name}'."
        if shared:
            message += f" Left alone, as they also cover other objects: {', '.join(shared)}."
        return message


def _member_selectors(resp: dict[str, Any] | None) -> list[Any]:
    member = ((resp or {}).get("data") or {}).get("member") or {}
    return [s.get("id") for s in member.get("selectors") or []]


def _selector_name(selector: dict[str, Any]) -> str:
    return str(selector.get("name") or selector.get("id"))


def _tagged(node: Node, tag_obj: dict[str, Any]) -> bool:
    """Whether the latest analysis put `node` in the tag (selected by any rule, not only by bhshell)."""
    return node.owned if tag_obj.get("type") == _TAG_TYPE["owned"] else node.tier_zero
