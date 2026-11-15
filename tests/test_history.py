from jpdfrsc.core.history import SnapshotHistory


def test_undo_redo_snapshot_flow():
    history = SnapshotHistory(limit=3)
    history.checkpoint("edit one", b"before")
    undo = history.take_undo(b"after")
    assert undo.data == b"before"
    redo = history.take_redo(b"before")
    assert redo.data == b"after"


def test_new_checkpoint_clears_redo():
    history = SnapshotHistory()
    history.checkpoint("edit", b"a")
    history.take_undo(b"b")
    history.checkpoint("new branch", b"c")
    assert history.take_redo(b"d") is None
