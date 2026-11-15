"""Reference graph analysis for PDF indirect objects.

The graph is observational: it never edits xref entries or deletes objects.
Direct containers are walked in-place and indirect references become graph edges.
"""
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Any


@dataclass
class GraphNode:
    ref: tuple[int, int]
    kind: str
    reachable: bool = False
    inbound: list[tuple[tuple[int, int] | None, str]] = field(default_factory=list)
    outbound: list[tuple[tuple[int, int], str]] = field(default_factory=list)


@dataclass
class ReferenceGraph:
    nodes: dict[tuple[int, int], GraphNode]
    root_ref: tuple[int, int] | None
    edges: list[tuple[tuple[int, int] | None, tuple[int, int], str]]

    @property
    def orphaned(self) -> list[GraphNode]:
        return [n for n in self.nodes.values() if not n.reachable]

    def summary(self) -> dict[str, int]:
        return {
            "objects": len(self.nodes),
            "reachable": sum(n.reachable for n in self.nodes.values()),
            "orphaned": len(self.orphaned),
            "references": len(self.edges),
            "cycles": len(self.cycle_edges()),
        }

    def cycle_edges(self) -> list[tuple[tuple[int, int] | None, tuple[int, int], str]]:
        """Return edges participating in a directed cycle (iterative Kosaraju SCC)."""
        adjacency: dict[tuple[int, int], list[tuple[int, int]]] = {r: [] for r in self.nodes}
        reverse: dict[tuple[int, int], list[tuple[int, int]]] = {r: [] for r in self.nodes}
        for source, target, _ in self.edges:
            if source in adjacency:
                adjacency[source].append(target)
                reverse[target].append(source)

        visited: set[tuple[int, int]] = set()
        finish: list[tuple[int, int]] = []
        for start in adjacency:
            if start in visited: continue
            stack = [(start, False)]
            while stack:
                vertex, expanded = stack.pop()
                if expanded:
                    finish.append(vertex)
                    continue
                if vertex in visited: continue
                visited.add(vertex)
                stack.append((vertex, True))
                for neighbor in adjacency.get(vertex, []):
                    if neighbor not in visited: stack.append((neighbor, False))

        assigned: set[tuple[int, int]] = set()
        cyclic: set[tuple[int, int]] = set()
        for start in reversed(finish):
            if start in assigned: continue
            component = []
            stack = [start]; assigned.add(start)
            while stack:
                vertex = stack.pop(); component.append(vertex)
                for neighbor in reverse.get(vertex, []):
                    if neighbor not in assigned:
                        assigned.add(neighbor); stack.append(neighbor)
            if len(component) > 1 or start in adjacency.get(start, []):
                cyclic.update(component)
        return [e for e in self.edges if e[0] in cyclic and e[1] in cyclic]

    def rows(self):
        return [self.nodes[r] for r in sorted(self.nodes)]


def _obj_ref(obj) -> tuple[int, int] | None:
    try:
        ref = tuple(obj.objgen)
        if len(ref) == 2 and ref != (0, 0):
            return int(ref[0]), int(ref[1])
    except Exception:
        pass
    return None


def _kind(obj) -> str:
    name = type(obj).__name__
    if name == "Stream": return "Stream"
    if name == "Dictionary": return "Dictionary"
    if name == "Array": return "Array"
    return name


def build_reference_graph(pdf) -> ReferenceGraph:
    """Build a reachable-reference graph from /Root and index all indirect objects."""
    nodes: dict[tuple[int, int], GraphNode] = {}
    for obj in pdf.objects:
        ref = _obj_ref(obj)
        if ref:
            nodes[ref] = GraphNode(ref, _kind(obj))

    root = getattr(pdf, "Root", None)
    root_ref = _obj_ref(root) if root is not None else None
    edges: list[tuple[tuple[int, int] | None, tuple[int, int], str]] = []
    visited: set[tuple[int, int]] = set()

    def walk(obj: Any, owner: tuple[int, int] | None, path: str, depth: int = 0):
        # Malformed PDFs can contain pathologically nested direct containers.
        if depth > 512 or len(edges) > 2_000_000:
            return
        ref = _obj_ref(obj)
        if ref:
            edge = (owner, ref, path)
            if edge not in edges: edges.append(edge)
            node = nodes.setdefault(ref, GraphNode(ref, _kind(obj)))
            node.reachable = True
            node.inbound.append((owner, path))
            if owner in nodes:
                nodes[owner].outbound.append((ref, path))
            if ref in visited: return
            visited.add(ref)
            owner = ref
        # pikepdf streams behave as dictionaries; inspect dictionary entries.
        if hasattr(obj, "items"):
            try:
                for key, value in obj.items():
                    walk(value, owner, f"{path}/{str(key).lstrip('/')}", depth + 1)
            except Exception:
                return
        elif isinstance(obj, (list, tuple)) or type(obj).__name__ == "Array":
            try:
                for i, value in enumerate(obj): walk(value, owner, f"{path}[{i}]", depth + 1)
            except Exception:
                return

    if root is not None:
        walk(root, None, "/Root")
    return ReferenceGraph(nodes, root_ref, edges)


def format_graph_report(graph: ReferenceGraph) -> str:
    s = graph.summary()
    lines = ["jPDFRsc REFERENCE GRAPH", "=" * 72,
             "Reachability is computed from the document catalog (/Root).",
             "Orphan candidates are not automatically safe to delete.", "",
             "SUMMARY"]
    lines.extend(f"{k}: {v}" for k, v in s.items())
    lines += ["", "OBJECTS", "Ref       Type         Reachability  Inbound  Outbound"]
    for n in graph.rows():
        lines.append(f"{n.ref[0]:<9} {n.kind:<12} {'reachable' if n.reachable else 'orphan-candidate':<14} {len(n.inbound):<8} {len(n.outbound)}")
    lines += ["", "REFERENCE EDGES"]
    for source, target, path in graph.edges:
        src = "ROOT" if source is None else f"{source[0]} {source[1]} R"
        lines.append(f"{src} -> {target[0]} {target[1]} R  [{path}]")
    lines += ["", "CYCLE EDGES"]
    for source, target, path in graph.cycle_edges():
        src = "ROOT" if source is None else f"{source[0]} {source[1]} R"
        lines.append(f"{src} -> {target[0]} {target[1]} R  [{path}]")
    return "\n".join(lines)
