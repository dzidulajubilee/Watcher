"""
Watcher IDS Dashboard — SSE Client Registry
Thread-safe fan-out of alert payloads to all connected browser clients.
"""

import json
import logging
import threading
from queue import Queue

from config import MAX_QUEUE

log = logging.getLogger("watcher.registry")


class Registry:
    """
    Maintains a set of per-client Queues.

    When a new alert arrives (from tail.py), broadcast() puts a formatted
    SSE message into every client's queue.  The HTTP handler thread for each
    client drains its queue and writes to the socket.

    Clients that have fallen behind (full queue) are silently dropped —
    they will reconnect automatically via the browser's EventSource retry.
    """

    def __init__(self):
        self._lock    = threading.Lock()
        self._clients: dict[int, Queue] = {}
        self._next_id = 0

    # ── Client lifecycle ──────────────────────────────────────────────────────

    def add(self) -> tuple[int, Queue]:
        """Register a new client. Returns (client_id, queue)."""
        with self._lock:
            cid = self._next_id
            self._next_id += 1
            self._clients[cid] = Queue(maxsize=MAX_QUEUE)
            log.info("Client connected    (total: %d)", len(self._clients))
            return cid, self._clients[cid]

    def remove(self, cid: int):
        """Unregister a client (called when its socket closes)."""
        with self._lock:
            self._clients.pop(cid, None)
            log.info("Client disconnected (total: %d)", len(self._clients))

    # ── Broadcast ─────────────────────────────────────────────────────────────

    def broadcast(self, event_type: str, payload: dict):
        """
        Serialize `payload` as an SSE event and enqueue it for
        every connected client.  Clients whose queues are full are dropped.
        event_type: 'alert' | 'flow' | 'dns' | 'http' | 'ping'
        """
        msg = f"event: {event_type}\ndata: {json.dumps(payload)}\n\n"
        with self._lock:
            dead = []
            for cid, q in self._clients.items():
                try:
                    q.put_nowait(msg)
                except Exception:
                    dead.append(cid)
            for cid in dead:
                self._clients.pop(cid, None)

    # ── Info ──────────────────────────────────────────────────────────────────

    def count(self) -> int:
        """Return the number of currently connected clients."""
        with self._lock:
            return len(self._clients)
