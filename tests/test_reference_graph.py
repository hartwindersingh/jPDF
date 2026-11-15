from jpdfrsc.core.reference_graph import build_reference_graph, format_graph_report


class Dictionary(dict):
    def __init__(self, objgen=(0, 0), **kwargs):
        super().__init__(**kwargs); self.objgen = objgen


class Array(list):
    objgen = (0, 0)


def test_graph_reachability_inbound_outbound_and_orphans():
    child = Dictionary((2, 0), Label="child")
    orphan = Dictionary((3, 0), Label="orphan")
    root = Dictionary((1, 0), Child=child, List=Array([child]))

    class PDF:
        Root = root
        objects = [root, child, orphan]

    graph = build_reference_graph(PDF())
    assert graph.summary()["objects"] == 3
    assert graph.nodes[(1, 0)].reachable
    assert graph.nodes[(2, 0)].reachable
    assert not graph.nodes[(3, 0)].reachable
    assert len(graph.nodes[(2, 0)].inbound) == 2
    assert len(graph.nodes[(1, 0)].outbound) == 2
    assert [n.ref for n in graph.orphaned] == [(3, 0)]
    assert "orphan-candidate" in format_graph_report(graph)


def test_graph_detects_indirect_cycles():
    first = Dictionary((1, 0))
    second = Dictionary((2, 0))
    first["Next"] = second
    second["Back"] = first

    class PDF:
        Root = first
        objects = [first, second]

    graph = build_reference_graph(PDF())
    assert len(graph.cycle_edges()) == 2
    assert graph.summary()["cycles"] == 2
