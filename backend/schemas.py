"""Validated request and response shapes for the AgentGuard API."""

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class ActionRequest(BaseModel):
    """An action proposed by a caller; parameter values are never trusted."""

    model_config = ConfigDict(extra="forbid")

    action_type: str = Field(min_length=1, max_length=32, pattern=r"^[a-z][a-z0-9_]*$")
    parameters: dict[str, str] = Field(max_length=8)


class ActionResponse(BaseModel):
    action_type: str
    decision: Literal["ALLOW", "BLOCK"]
    reason: str
    content: str | None = None
