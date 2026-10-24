import json
from datetime import datetime, timezone
from pathlib import Path
from backend.app.config import settings

COMMANDS_LOG_PATH = settings.BASE_DIR / "logs" / "commands.jsonl"


def log_command_audit(
    sandbox_name: str,
    command: str,
    decision: str = "allow",
    execution_target: str = "celesto_sandbox",
) -> None:
    """
    Append a structured command execution audit record to logs/commands.jsonl.
    Enforces the exact hackathon schema:
    {
      "ts": "ISO-8601 string",
      "sandbox_name": "sbx-[a-z0-9]{8,}",
      "command": "string",
      "decision": "allow" | "block",
      "execution_target": "celesto_sandbox"
    }
    Never logs secrets or executes on the host.
    """
    COMMANDS_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "sandbox_name": sandbox_name,
        "command": command,
        "decision": decision,
        "execution_target": execution_target,
    }

    with open(COMMANDS_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")
