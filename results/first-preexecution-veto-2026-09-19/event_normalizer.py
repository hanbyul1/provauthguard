from __future__ import annotations

import json
import re
import shlex
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROTECTED_ROOT = (Path.home() / "guardian-study" / "protected").resolve()

READ_COMMANDS = {
    "cat", "sed", "head", "tail", "less", "more",
    "wc", "grep", "awk"
}


@dataclass
class NormalizedEvent:
    event_id: str
    timestamp: str
    actor: str
    tool: str
    action: str
    resource: str | None
    destination: str | None
    protected: bool
    source_tool_call_id: str | None
    source_run_id: str | None


def canonicalize_path(value: str) -> str:
    return str(Path(value).expanduser().resolve(strict=False))


def is_protected(resource: str | None) -> bool:
    if not resource:
        return False

    try:
        p = Path(resource).expanduser().resolve(strict=False)
        return p == PROTECTED_ROOT or PROTECTED_ROOT in p.parents
    except Exception:
        return False


def extract_paths_from_command(command: str) -> list[str]:
    paths: list[str] = []

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    for token in tokens:
        token = token.strip(";,()")

        # curl-style @file argument
        if token.startswith("@/"):
            token = token[1:]

        if token.startswith("~/"):
            token = str(Path(token).expanduser())

        if token.startswith("/"):
            paths.append(canonicalize_path(token))

    return list(dict.fromkeys(paths))


def classify_curl(command: str) -> tuple[str, str | None, str | None] | None:
    """
    Recognize outbound curl operations.

    For the current experiment:
      curl ... --data-binary @FILE URL

    becomes:
      action      = network_send
      resource    = FILE
      destination = URL
    """
    try:
        tokens = shlex.split(command)
    except ValueError:
        return None

    if not tokens:
        return None

    # curl may not necessarily be token 0 in every future command,
    # but require an actual curl command token for this experiment.
    curl_positions = [
        i for i, token in enumerate(tokens)
        if Path(token).name == "curl"
    ]

    if not curl_positions:
        return None

    resource: str | None = None
    destination: str | None = None

    for i, token in enumerate(tokens):
        # --data-binary @/path/file
        if token == "--data-binary" and i + 1 < len(tokens):
            value = tokens[i + 1]
            if value.startswith("@"):
                candidate = value[1:]
                if candidate.startswith("/") or candidate.startswith("~/"):
                    resource = canonicalize_path(candidate)

        # --data-binary=@/path/file
        elif token.startswith("--data-binary="):
            value = token.split("=", 1)[1]
            if value.startswith("@"):
                candidate = value[1:]
                if candidate.startswith("/") or candidate.startswith("~/"):
                    resource = canonicalize_path(candidate)

        if token.startswith(("http://", "https://")):
            destination = token

    if destination is not None:
        return "network_send", resource, destination

    return None


def classify_exec(
    command: str,
) -> tuple[str, str | None, str | None]:

    curl_result = classify_curl(command)

    if curl_result is not None:
        return curl_result

    paths = extract_paths_from_command(command)

    try:
        tokens = shlex.split(command)
    except ValueError:
        tokens = command.split()

    command_names: set[str] = set()

    for token in tokens:
        base = Path(token).name

        if (
            token in {"&&", "||", "|", ";"}
            or token.startswith("-")
            or token.startswith("/")
            or token.startswith("~/")
        ):
            continue

        command_names.add(base)

    if command_names & READ_COMMANDS and paths:
        return "file_read", paths[0], None

    return (
        "command_execute",
        paths[0] if paths else None,
        None,
    )


def classify_apply_patch(
    params: dict[str, Any],
) -> tuple[str, str | None, str | None]:

    command = str(params.get("command", ""))

    # Example:
    # *** Add File: /Users/.../workspace/report.txt
    match = re.search(
        r"^\*\*\* Add File:\s+(.+?)\s*$",
        command,
        flags=re.MULTILINE,
    )

    if match:
        path = match.group(1).strip()

        if path.startswith("/") or path.startswith("~/"):
            return "file_write", canonicalize_path(path), None

        return "file_write", path, None

    # Future patches may modify existing files.
    match = re.search(
        r"^\*\*\* Update File:\s+(.+?)\s*$",
        command,
        flags=re.MULTILINE,
    )

    if match:
        path = match.group(1).strip()

        if path.startswith("/") or path.startswith("~/"):
            return "file_write", canonicalize_path(path), None

        return "file_write", path, None

    return "tool_call", None, None


def normalize_openclaw_event(raw: dict[str, Any]) -> NormalizedEvent:
    tool = str(raw.get("toolName", "unknown"))
    params = raw.get("params") or {}

    action = "tool_call"
    resource: str | None = None
    destination: str | None = None

    if tool == "exec":
        command = str(params.get("command", ""))
        action, resource, destination = classify_exec(command)

    elif tool == "apply_patch":
        action, resource, destination = classify_apply_patch(params)

    return NormalizedEvent(
        event_id=str(uuid.uuid4()),
        timestamp=str(
            raw.get("timestamp")
            or datetime.now(timezone.utc).isoformat()
        ),
        actor=str(raw.get("actor", "worker")),
        tool=tool,
        action=action,
        resource=resource,
        destination=destination,
        protected=is_protected(resource),
        source_tool_call_id=raw.get("toolCallId"),
        source_run_id=raw.get("runId"),
    )


def normalize_file(
    raw_log: Path,
    normalized_log: Path,
) -> None:
    normalized_log.parent.mkdir(parents=True, exist_ok=True)

    with raw_log.open("r", encoding="utf-8") as src, \
         normalized_log.open("w", encoding="utf-8") as dst:

        for line in src:
            line = line.strip()

            if not line:
                continue

            raw = json.loads(line)
            event = normalize_openclaw_event(raw)

            dst.write(
                json.dumps(
                    asdict(event),
                    ensure_ascii=False
                ) + "\n"
            )


if __name__ == "__main__":
    root = Path.home() / "guardian-study"

    raw_log = root / "logs" / "openclaw_tool_events.jsonl"
    normalized_log = root / "logs" / "normalized_events.jsonl"

    if not raw_log.exists():
        raise SystemExit(f"Raw log not found: {raw_log}")

    normalize_file(raw_log, normalized_log)

    print(f"Normalized events written to: {normalized_log}")
