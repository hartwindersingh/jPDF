"""Byte-snapshot undo/redo history for safe, document-wide rollback."""
from __future__ import annotations
from dataclasses import dataclass

@dataclass
class Snapshot:
    label: str
    data: bytes

class SnapshotHistory:
    def __init__(self, limit: int = 20):
        self.limit = limit
        self.undo_stack: list[Snapshot] = []
        self.redo_stack: list[Snapshot] = []

    def checkpoint(self, label: str, data: bytes):
        self.undo_stack.append(Snapshot(label, data))
        if len(self.undo_stack) > self.limit:
            self.undo_stack.pop(0)
        self.redo_stack.clear()

    def take_undo(self, current: bytes) -> Snapshot | None:
        if not self.undo_stack:
            return None
        target = self.undo_stack.pop()
        self.redo_stack.append(Snapshot(target.label, current))
        return target

    def take_redo(self, current: bytes) -> Snapshot | None:
        if not self.redo_stack:
            return None
        target = self.redo_stack.pop()
        self.undo_stack.append(Snapshot(target.label, current))
        return target

    def clear(self):
        self.undo_stack.clear()
        self.redo_stack.clear()
