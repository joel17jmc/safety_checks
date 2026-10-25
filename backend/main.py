"""FastAPI application for the AgentGuard AI demo."""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend import audit
from backend.schemas import ActionRequest, ActionResponse
from backend.security import check_action, execute_action

MAX_REQUEST_BYTES = 8_192

app = FastAPI(title="AgentGuard AI", version="0.1.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:5500"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class RequestSizeLimitMiddleware:
    """Reject oversized request bodies before FastAPI parses them."""

    def __init__(self, application, max_bytes: int) -> None:
        self.application = application
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.application(scope, receive, send)
            return

        body = bytearray()
        too_large = False
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            body.extend(message.get("body", b""))
            if len(body) > self.max_bytes:
                too_large = True
                break
            if not message.get("more_body", False):
                break

        if too_large:
            response = JSONResponse(
                status_code=413,
                content={"detail": "Request body is too large."},
            )
            await response(scope, receive, send)
            return

        sent = False

        async def replay_body():
            nonlocal sent
            if sent:
                return {"type": "http.request", "body": b"", "more_body": False}
            sent = True
            return {"type": "http.request", "body": bytes(body), "more_body": False}

        await self.application(scope, replay_body, send)


app.add_middleware(RequestSizeLimitMiddleware, max_bytes=MAX_REQUEST_BYTES)


@app.exception_handler(RequestValidationError)
async def safe_validation_error(_request: Request, _error: RequestValidationError):
    return JSONResponse(status_code=422, content={"detail": "Invalid request."})


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/events")
def get_events() -> dict[str, object]:
    total, allowed, blocked = audit.event_totals()
    return {
        "total_actions": total,
        "allowed_actions": allowed,
        "blocked_actions": blocked,
        "events": audit.recent_events(),
    }


@app.post(
    "/actions/check",
    response_model=ActionResponse,
    response_model_exclude_none=True,
)
def check_requested_action(action: ActionRequest) -> ActionResponse:
    decision = check_action(action.action_type, action.parameters)
    audit.record_event(
        action.action_type,
        "ALLOW" if decision.allowed else "BLOCK",
        decision.reason,
    )
    return ActionResponse(
        action_type=action.action_type,
        decision="ALLOW" if decision.allowed else "BLOCK",
        reason=decision.reason,
    )


@app.post(
    "/actions/execute",
    response_model=ActionResponse,
    response_model_exclude_none=True,
)
def execute_requested_action(action: ActionRequest) -> ActionResponse:
    decision, content = execute_action(action.action_type, action.parameters)
    audit.record_event(
        action.action_type,
        "ALLOW" if decision.allowed else "BLOCK",
        decision.reason,
    )
    return ActionResponse(
        action_type=action.action_type,
        decision="ALLOW" if decision.allowed else "BLOCK",
        reason=decision.reason,
        content=content,
    )
