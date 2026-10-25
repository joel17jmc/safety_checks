"""Policy checks and the single permitted demo action."""

from dataclasses import dataclass
from pathlib import Path


WORKSPACE_DIR = Path(__file__).resolve().parent / "workspace"
APPROVED_FILE = "example.txt"
MAX_FILE_BYTES = 16_384


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def check_action(action_type: str, parameters: dict[str, str]) -> Decision:
    """Allow only reading the single approved text file."""
    if action_type != "read_file":
        return Decision(False, "This action type is not permitted.")

    if set(parameters) != {"file_name"}:
        return Decision(False, "The request must contain only a file_name parameter.")

    file_name = parameters["file_name"]
    if file_name != APPROVED_FILE:
        return Decision(False, "Only the approved demo file can be read.")

    if WORKSPACE_DIR.is_symlink():
        return Decision(False, "The demo workspace cannot be a symbolic link.")

    workspace = WORKSPACE_DIR.resolve()
    candidate = WORKSPACE_DIR / file_name
    if candidate.is_symlink():
        return Decision(False, "Symbolic links are not permitted.")

    resolved_candidate = candidate.resolve()
    if resolved_candidate.parent != workspace:
        return Decision(False, "The requested file is outside the demo workspace.")

    if not resolved_candidate.is_file():
        return Decision(False, "The approved file is unavailable.")

    try:
        if resolved_candidate.stat().st_size > MAX_FILE_BYTES:
            return Decision(False, "The approved file exceeds the size limit.")
    except OSError:
        return Decision(False, "The approved file is unavailable.")

    return Decision(True, "The approved demo file may be read.")


def execute_action(action_type: str, parameters: dict[str, str]) -> tuple[Decision, str | None]:
    """Recheck policy immediately before reading the approved file."""
    decision = check_action(action_type, parameters)
    if not decision.allowed:
        return decision, None

    try:
        with (WORKSPACE_DIR / APPROVED_FILE).open("rb") as approved_file:
            file_bytes = approved_file.read(MAX_FILE_BYTES + 1)
        if len(file_bytes) > MAX_FILE_BYTES:
            return Decision(False, "The approved file exceeds the size limit."), None
        content = file_bytes.decode("utf-8")
    except (OSError, UnicodeError):
        return Decision(False, "The approved file could not be read."), None

    return decision, content
