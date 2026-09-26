"""
Assignment 11 — Audit Log starter (TODO).

Records every interaction for forensics. Never blocks by itself —
other layers catch attacks; this layer makes them reviewable.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path


def default_audit_log_path() -> str:
    """Always resolve to <repo>/outputs/… (safe when cwd is src/)."""
    repo_root = Path(__file__).resolve().parents[2]
    return str(repo_root / "outputs" / "audit_log.json")


class AuditLogPlugin:
    """Framework-agnostic audit logger (wire into ADK callbacks or your pipeline)."""

    def __init__(self):
        self.name = "audit_log"
        self.logs: list[dict] = []
        self._open: dict[str, float] = {}

    def record_input(self, *, user_id: str, text: str, request_id: str | None = None):
        """Store input + start timestamp keyed by request_id/user_id."""
        import time

        key = request_id or f"{user_id}:{len(self.logs)}"
        self._open[key] = time.time()
        self._open[f"{key}:meta"] = {"user_id": user_id, "text": text,
                                     "request_id": request_id, "started_at": utc_now_iso()}

    def record_output(
        self,
        *,
        user_id: str,
        text: str,
        blocked: bool = False,
        layer: str | None = None,
        request_id: str | None = None,
    ):
        """Store output, layer decision, latency; append to self.logs."""
        import time

        key = request_id or f"{user_id}:{len(self.logs)}"
        start = self._open.pop(key, None)
        meta = self._open.pop(f"{key}:meta", {})
        latency = (time.time() - start) if isinstance(start, float) else 0.0
        self.logs.append({
            "user_id": meta.get("user_id", user_id) if isinstance(meta, dict) else user_id,
            "input": meta.get("text", "") if isinstance(meta, dict) else "",
            "output_preview": (text or "")[:300],
            "blocked": bool(blocked),
            "layer": layer,
            "latency_s": round(latency, 4),
            "request_id": request_id,
            "at": utc_now_iso(),
        })

    def export_json(self, filepath: str | None = None):
        """Write logs to disk (JSON array) under repo-root ``outputs/`` by default."""
        path = Path(filepath or default_audit_log_path())
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(self.logs, ensure_ascii=False, indent=2), encoding="utf-8")
        return str(path)


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()
