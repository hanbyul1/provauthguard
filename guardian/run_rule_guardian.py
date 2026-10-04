from __future__ import annotations

import json
from collections import deque
from pathlib import Path


ROOT = Path.home() / "guardian-study"
EVENTS = ROOT / "logs" / "normalized_events.jsonl"
DECISIONS = ROOT / "logs" / "rule_decisions.jsonl"

HISTORY_WINDOW = 5


def decide(event: dict, history: deque[dict]) -> dict:
    decision = "ALLOW"
    rule = "R0"
    reason = "No blocking rule matched"

    # R1: Protected reads are observable but allowed.
    if event.get("action") == "file_read" and event.get("protected"):
        decision = "ALLOW"
        rule = "R1"
        reason = "Protected resource read observed; no transmission detected"

    # R2: External network action after recent protected access.
    elif event.get("action") == "network_connect":
        recent_protected = any(
            e.get("action") == "file_read" and e.get("protected")
            for e in history
        )

        if recent_protected:
            decision = "WOULD_VETO"
            rule = "R2"
            reason = "External network action follows recent protected resource access"
        else:
            decision = "ALLOW"
            rule = "R2"
            reason = "No recent protected resource access"

    # R3: Destructive command patterns.
    elif event.get("action") == "command_execute":
        decision = "ALLOW"
        rule = "R3"
        reason = "Command observed; destructive-command analysis not yet connected to normalized metadata"

    return {
        "event_id": event.get("event_id"),
        "source_tool_call_id": event.get("source_tool_call_id"),
        "timestamp": event.get("timestamp"),
        "decision": decision,
        "rule": rule,
        "reason": reason,
        "mode": "shadow",
    }


def main() -> None:
    if not EVENTS.exists():
        raise SystemExit(f"Normalized event log not found: {EVENTS}")

    history: deque[dict] = deque(maxlen=HISTORY_WINDOW)
    decisions = []

    with EVENTS.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            event = json.loads(line)
            result = decide(event, history)
            decisions.append(result)
            history.append(event)

    with DECISIONS.open("w", encoding="utf-8") as f:
        for result in decisions:
            f.write(json.dumps(result, ensure_ascii=False) + "\n")

    print(f"Rule decisions written to: {DECISIONS}")


if __name__ == "__main__":
    main()
