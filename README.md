# AgentGuard AI

AgentGuard AI is a small local learning project that checks proposed agent actions against a backend-owned policy. The only permitted operation is reading `backend/workspace/example.txt`. The service does not invoke a shell, accept arbitrary file paths, or use an AI model or database.

This is an educational prototype, not production-grade security software. It demonstrates a narrow allowlist, input validation, a restricted workspace, and privacy-conscious event logging; it does not protect against a hostile process or administrator who can modify the application or workspace on the same computer.

## Project files

| File | What it does and how it connects |
| --- | --- |
| `backend/main.py` | Creates the FastAPI app and its health, event, check, and execute endpoints. It uses schemas to validate requests, the security module for decisions and reads, and the audit module to record decisions. |
| `backend/security.py` | Contains the backend allowlist, workspace boundary checks, symlink rejection, file-size limit, and the permitted file read. Both action endpoints use this security layer; execution checks policy again immediately before reading. |
| `backend/audit.py` | Writes minimal JSON Lines events and returns recent events and totals to the API. It never receives or stores request parameters or file contents. |
| `backend/schemas.py` | Defines Pydantic request and response models. Invalid shapes are rejected before policy code runs. |
| `backend/workspace/example.txt` | The sole approved demo file. It is deliberately ordinary sample text, not a place for secrets. |
| `frontend/index.html` | Provides the dashboard structure and links its stylesheet and JavaScript. |
| `frontend/style.css` | Styles a responsive, dark dashboard with metric cards and an event table. |
| `frontend/app.js` | Fetches the API's event summary and safely renders it as text; it does not make policy decisions. |
| `tests/test_security.py` | Exercises the API with allowed, prohibited, malformed, oversized, traversal, and symlink inputs, and checks audit privacy. |
| `requirements.txt` | Lists the API server and test dependencies. |
| `.gitignore` | Excludes Python caches, virtual environments, test caches, and the generated audit file. |

## Install and run on Windows

Run these commands from the project root in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

If PowerShell blocks environment activation, use the interpreter directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Start the API in the first terminal. Uvicorn binds to localhost only:

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

In a second terminal from the project root, serve the dashboard locally:

```powershell
python -m http.server 5500 --bind 127.0.0.1 --directory frontend
```

Open `http://127.0.0.1:5500` in a browser. The dashboard reads summary events from the API at `http://127.0.0.1:8000`. Use the API's interactive documentation at `http://127.0.0.1:8000/docs` to try `POST /actions/check` or `POST /actions/execute` with:

```json
{
  "action_type": "read_file",
  "parameters": {
    "file_name": "example.txt"
  }
}
```

Run the security tests from the project root:

```powershell
python -m pytest -q
```

## How an action is handled

1. FastAPI parses the JSON body into the Pydantic request model. Extra properties, missing parameters, invalid action names, malformed JSON, and bodies over 8 KiB are rejected.
2. The security layer recognizes only `read_file`, requires exactly the `file_name` parameter, and permits only `example.txt`. It checks the resolved workspace location and rejects symbolic links.
3. `/actions/check` returns the policy result without reading the file. `/actions/execute` calls the same policy check immediately before the permitted read. No shell execution exists in the implementation.
4. The audit module writes a JSON object per line with a UTC timestamp, action type, decision, and fixed reason. The event endpoint exposes those fields and totals only.
5. The browser displays backend-provided events. Its text is inserted with `textContent`, not interpreted as HTML.

## Prototype limitations

- This narrow demo only supports one fixed file; it is not a general-purpose agent sandbox.
- A same-user local process that can alter the source, audit file, or workspace may undermine this demo. Filesystem checks do not claim protection against a privileged or actively racing local attacker.
- The JSONL audit log is local and append-only by convention, not tamper-proof, encrypted, rotated, or suitable for multi-process coordination.
- There is no authentication or authorization. Keep the server bound to localhost, and do not expose it to a network.
- The dashboard's local HTTP server and the API are for development only. Neither should be treated as a production deployment.
