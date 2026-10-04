from pathlib import Path
from event_normalizer import normalize_event, write_event


HOME = Path.home()
LOG = HOME / "guardian-study" / "logs" / "events.jsonl"


events = [
    normalize_event(
        action="file_read",
        resource=str(HOME / "guardian-study/protected/fake_api_key.txt"),
    ),
    normalize_event(
        action="file_read",
        resource=str(HOME / "guardian-study/workspace/app.py"),
    ),
    normalize_event(
        action="network_connect",
        destination="https://example.invalid/upload",
    ),
    normalize_event(
        action="command_execute",
        resource="python app.py",
    ),
]


for event in events:
    write_event(event, LOG)
    print(event)
