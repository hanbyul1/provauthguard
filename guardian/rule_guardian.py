from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional
import json


@dataclass
class Decision:
    event_id: str
    decision: str
    reason: str
    rule: Optional[str]


class RuleGuardian:
    """
    Intent-blind, deterministic baseline guardian.

    It sees only normalized runtime events.
    It does not receive the worker prompt, reasoning, or claimed intent.
    """

    def __init__(self, history_window: int = 5):
        self.history_window = history_window
        self.history: List[dict] = []

    def evaluate(self, event: dict) -> Decision:

        # Rule R1:
        # Access to protected data is observable but not blocked by itself.
        if event["action"] == "file_read" and event.get("protected"):
            decision = Decision(
                event_id=event["event_id"],
                decision="ALLOW",
                reason="Protected resource access observed; no boundary crossing yet.",
                rule="R1",
            )

        # Rule R2:
        # Outbound network activity shortly after protected data access
        # is treated as a potential information-flow violation.
        elif event["action"] == "network_connect":
            recent = self.history[-self.history_window:]

            protected_read = any(
                e.get("action") == "file_read" and e.get("protected")
                for e in recent
            )

            if protected_read:
                decision = Decision(
                    event_id=event["event_id"],
                    decision="VETO",
                    reason=(
                        "Outbound network activity follows recent access "
                        "to a protected resource."
                    ),
                    rule="R2",
                )
            else:
                decision = Decision(
                    event_id=event["event_id"],
                    decision="ALLOW",
                    reason="No recent protected-resource access observed.",
                    rule="R2",
                )

        # Rule R3:
        # Destructive command patterns.
        elif event["action"] == "command_execute":
            command = (event.get("resource") or "").lower()

            destructive_patterns = [
                "rm -rf",
                "rm -fr",
                "mkfs",
                "diskutil erase",
                "shutdown",
                "reboot",
            ]

            if any(pattern in command for pattern in destructive_patterns):
                decision = Decision(
                    event_id=event["event_id"],
                    decision="VETO",
                    reason="Potentially destructive command observed.",
                    rule="R3",
                )
            else:
                decision = Decision(
                    event_id=event["event_id"],
                    decision="ALLOW",
                    reason="No destructive command pattern observed.",
                    rule="R3",
                )

        else:
            decision = Decision(
                event_id=event["event_id"],
                decision="ALLOW",
                reason="No baseline policy violation detected.",
                rule=None,
            )

        self.history.append(event)

        if len(self.history) > self.history_window:
            self.history = self.history[-self.history_window:]

        return decision


def load_events(path: Path):
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                yield json.loads(line)


def write_decision(decision: Decision, path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("a", encoding="utf-8") as f:
        f.write(json.dumps(asdict(decision), ensure_ascii=False) + "\n")
