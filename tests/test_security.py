"""API tests for action policy, request validation, and audit privacy."""

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from backend import audit
from backend.main import app


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(audit, "AUDIT_LOG_PATH", tmp_path / "audit.jsonl")
    with TestClient(app) as test_client:
        yield test_client


def test_health_endpoint(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_approved_file_is_allowed_and_read(client):
    response = client.post(
        "/actions/execute",
        json={"action_type": "read_file", "parameters": {"file_name": "example.txt"}},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "ALLOW"
    assert "harmless sample text" in response.json()["content"]
    assert "SIMULATED SECURITY TEST FILE" not in response.json()["content"]


@pytest.mark.parametrize(
    ("action_type", "parameters"),
    [
        ("run_shell", {"command": "whoami"}),
        ("delete_file", {"file_name": "example.txt"}),
        ("read_file", {"file_name": "malware_test.txt"}),
        ("read_file", {"file_name": "..\\..\\secrets.txt"}),
        ("read_file", {"file_name": "../secrets.txt"}),
        ("read_file", {"file_name": "other.txt"}),
    ],
)
def test_prohibited_actions_are_blocked(client, action_type, parameters):
    response = client.post(
        "/actions/check",
        json={"action_type": action_type, "parameters": parameters},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["reason"]
    assert "content" not in response.json()


def test_malware_test_file_is_blocked_without_exposing_its_contents(client):
    response = client.post(
        "/actions/execute",
        json={
            "action_type": "read_file",
            "parameters": {"file_name": "malware_test.txt"},
        },
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert response.json()["reason"] == "Only the approved demo file can be read."
    assert "content" not in response.json()
    assert "SIMULATED SECURITY TEST FILE" not in response.text


def test_missing_parameters_are_rejected(client):
    response = client.post("/actions/check", json={"action_type": "read_file"})
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request."}


def test_malformed_json_is_rejected_without_echoing_input(client):
    response = client.post(
        "/actions/check",
        content=b'{"action_type":',
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 422
    assert response.json() == {"detail": "Invalid request."}


def test_oversized_body_is_rejected(client):
    response = client.post(
        "/actions/check",
        content=b" " * 8193,
        headers={"Content-Type": "application/json"},
    )
    assert response.status_code == 413
    assert response.json() == {"detail": "Request body is too large."}


def test_outside_symlink_is_blocked(client, tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    link = workspace / "example.txt"
    link.write_text("must remain private", encoding="utf-8")
    monkeypatch.setattr("backend.security.WORKSPACE_DIR", workspace)
    monkeypatch.setattr(Path, "is_symlink", lambda path: path == link)
    response = client.post(
        "/actions/execute",
        json={"action_type": "read_file", "parameters": {"file_name": "example.txt"}},
    )
    assert response.status_code == 200
    assert response.json()["decision"] == "BLOCK"
    assert "must remain private" not in response.text


def test_audit_log_and_events_endpoint_exclude_file_contents(client):
    client.post(
        "/actions/execute",
        json={"action_type": "read_file", "parameters": {"file_name": "example.txt"}},
    )
    log_data = audit.AUDIT_LOG_PATH.read_text(encoding="utf-8")
    logged_event = json.loads(log_data)
    assert set(logged_event) == {"timestamp", "action_type", "decision", "reason"}
    assert "only file AgentGuard AI permits" not in log_data

    response = client.get("/events")
    assert response.status_code == 200
    data = response.json()
    assert data["total_actions"] == 1
    assert data["allowed_actions"] == 1
    assert data["blocked_actions"] == 0
    assert "content" not in data["events"][0]


def test_allowed_and_blocked_actions_appear_in_event_history(client):
    allowed = client.post(
        "/actions/execute",
        json={"action_type": "read_file", "parameters": {"file_name": "example.txt"}},
    )
    blocked = client.post(
        "/actions/execute",
        json={
            "action_type": "read_file",
            "parameters": {"file_name": "malware_test.txt"},
        },
    )
    assert allowed.json()["decision"] == "ALLOW"
    assert "harmless sample text" in allowed.json()["content"]
    assert blocked.json()["decision"] == "BLOCK"

    events = client.get("/events").json()
    assert events["total_actions"] == 2
    assert events["allowed_actions"] == 1
    assert events["blocked_actions"] == 1
    assert [event["decision"] for event in events["events"]] == ["BLOCK", "ALLOW"]
    assert all("content" not in event for event in events["events"])
