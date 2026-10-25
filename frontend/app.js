const API_URL = "http://127.0.0.1:8000";

const totalCount = document.querySelector("#total-count");
const allowedCount = document.querySelector("#allowed-count");
const blockedCount = document.querySelector("#blocked-count");
const eventsList = document.querySelector("#events-list");
const errorMessage = document.querySelector("#error-message");
const lastUpdated = document.querySelector("#last-updated");
const runAllowedButton = document.querySelector("#run-allowed-button");
const runBlockedButton = document.querySelector("#run-blocked-button");
const actionResult = document.querySelector("#action-result");

function renderEvents(events) {
  eventsList.replaceChildren();
  if (events.length === 0) {
    const row = document.createElement("tr");
    const cell = document.createElement("td");
    cell.colSpan = 4;
    cell.className = "empty-state";
    cell.textContent = "No security events recorded.";
    row.append(cell);
    eventsList.append(row);
    return;
  }

  for (const event of events) {
    const row = document.createElement("tr");
    const time = document.createElement("td");
    const action = document.createElement("td");
    const decisionCell = document.createElement("td");
    const reason = document.createElement("td");
    const badge = document.createElement("span");

    time.textContent = new Date(event.timestamp).toLocaleString();
    action.textContent = event.action_type;
    badge.className = `decision ${event.decision === "ALLOW" ? "allow" : "block"}`;
    badge.textContent = event.decision;
    decisionCell.append(badge);
    reason.textContent = event.reason;
    row.append(time, action, decisionCell, reason);
    eventsList.append(row);
  }
}

async function refreshDashboard() {
  errorMessage.hidden = true;
  try {
    const response = await fetch(`${API_URL}/events`);
    if (!response.ok) throw new Error("The API returned an error.");
    const data = await response.json();
    totalCount.textContent = data.total_actions;
    allowedCount.textContent = data.allowed_actions;
    blockedCount.textContent = data.blocked_actions;
    renderEvents(data.events);
    lastUpdated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
  } catch {
    errorMessage.textContent = "Could not reach the API. Start the backend and try again.";
    errorMessage.hidden = false;
    lastUpdated.textContent = "API unavailable";
  }
}

async function runAction(fileName, label) {
  runAllowedButton.disabled = true;
  runBlockedButton.disabled = true;
  actionResult.className = "action-result";
  actionResult.textContent = `${label} is being checked by the backend…`;

  try {
    const response = await fetch(`${API_URL}/actions/execute`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        action_type: "read_file",
        parameters: { file_name: fileName },
      }),
    });
    if (!response.ok) throw new Error("The API returned an error.");
    const result = await response.json();
    actionResult.className = `action-result ${result.decision === "ALLOW" ? "result-allow" : "result-block"}`;
    const allowedContent = result.decision === "ALLOW" ? result.content : null;
    actionResult.textContent = `${result.decision}: ${result.reason}${allowedContent ? ` ${allowedContent}` : ""}`;
    await refreshDashboard();
  } catch {
    actionResult.className = "action-result result-error";
    actionResult.textContent = "Could not reach the API. Start the backend, then try again.";
  } finally {
    runAllowedButton.disabled = false;
    runBlockedButton.disabled = false;
  }
}

document.querySelector("#refresh-button").addEventListener("click", refreshDashboard);
runAllowedButton.addEventListener("click", () => runAction("example.txt", "Allowed file"));
runBlockedButton.addEventListener("click", () => runAction("malware_test.txt", "Blocked file"));
refreshDashboard();
