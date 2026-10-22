# MailGuard

**MailGuard** is a security-first personal AI communication gatekeeper with isolated Celesto sandbox quarantine, delimited LLM advisory evaluation, and human-gated action authorization.

---

## Architecture & Security Boundaries

```text
Untrusted Email
      ↓
Phase 2A Static Inspection (Celesto MicroVM or Subprocess Isolation, Network: OFF)
      ↓
Validated Sandbox Inspection Result (Pydantic schema, size bounded <= 512KB)
      ↓
Phase 2B Advisory LLM Analysis (Strict XML Fencing <untrusted_email_body>, Zero Tools)
      ↓
Deterministic Policy Engine (Rule-based evaluation -> Action Proposal)
      ↓
PENDING_APPROVAL (Strictly halted state; zero execution permitted)
      ↓
Explicit Human Decision
      ├── APPROVED ➔ EXECUTABLE ➔ Action Executor (Safe simulated driver) ➔ EXECUTED
      └── REJECTED ➔ TERMINAL
```

### Core Security Invariants & Guarantees
- **LLM Recommendation ≠ Authorization:** The LLM is strictly an advisory evaluator. An LLM output recommendation (e.g. `recommended_action: "QUARANTINE"`) cannot authorize, schedule, or execute any action.
- **Policy Engine ≠ Human Approval:** The deterministic Policy Engine evaluates static heuristics and advisory LLM findings to propose actions. All proposals are created strictly in the `PENDING_APPROVAL` state.
- **Human Approval = Permission to Execute:** Only explicit human decisions can transition an action from `PENDING_APPROVAL` to `APPROVED`.
- **Executor Runs Only Approved Actions:** The Action Executor layer strictly verifies `state == APPROVED` before performing any operation. Replay protection prevents executing an action more than once.
- **Simulated Execution (Phase 3 Notice):** Phase 3 uses safe simulated executors. No real Gmail, Google Calendar, or social-media APIs are invoked.
- **Advisory LLM Only:** The LLM operates with **zero tools**, zero shell commands, zero filesystem access, and zero network access.
- **Strict Prompt / Data Separation:** Untrusted email text is isolated within `<untrusted_email_body>` tags with closing tag sanitization to prevent fence breakouts.
- **No Raw Sandbox Forwarding:** Raw `stdout` / `stderr` is never passed directly to the LLM. Only validated Pydantic models reach the evaluator.
- **Quarantine Boundary:** Ephemeral Celesto microVMs run with network egress disabled (`network_policy={"mode": "off"}`). Zero attachment execution.

### Security Limitations & Disclaimer
- **Probabilistic Threat Detection:** LLM security analysis and static heuristics are probabilistic and advisory. MailGuard does **not** claim 100% detection of all zero-day phishing or advanced evasion attacks.
- **Mandatory Human Approval:** Because automated AI classifications can yield false positives or false negatives, all external side effects require explicit human verification and approval.

---

## Action State Machine

The Policy Engine and Action Approval workflow enforce a deterministic state machine:

| Initial State | Event / Trigger | Target State | Permitted? |
|---|---|---|:---:|
| `PENDING_APPROVAL` | Human Approval (`/approve`) | `APPROVED` | **Yes** |
| `PENDING_APPROVAL` | Human Rejection (`/reject`) | `REJECTED` | **Yes** |
| `APPROVED` | Execution Driver Success (`/execute`) | `EXECUTED` | **Yes** |
| `APPROVED` | Execution Driver Error (`/execute`) | `FAILED` | **Yes** |
| `PENDING_APPROVAL` | Attempt Execution (`/execute`) | *Blocked (HTTP 403)* | **No** |
| `REJECTED` | Attempt Approval or Execution | *Blocked (HTTP 400/403)* | **No** |
| `EXECUTED` | Attempt Re-execution (Replay) | *Blocked (HTTP 403)* | **No** |
| `FAILED` | Attempt Re-execution | *Blocked (HTTP 403)* | **No** |

---

## Supported LLM Providers

1. **`mock` (Default)**:
   - Zero-credential offline deterministic evaluator.
   - Evaluates benign messages, phishing attempts, adversarial prompt injections, urgency ratings (1–5), and structured calendar events without external AI services.
2. **`ollama`**:
   - Local model inference via Ollama HTTP API (e.g. `llama3.2`, `qwen2.5`).
   - Pure JSON structured output mode with temperature 0.0 and zero tool definitions.

---

## Running MailGuard

### 1. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

#### Running with Mock LLM (Default Offline Setup)
```ini
LLM_PROVIDER=mock
SANDBOX_PROVIDER_MODE=auto
```

#### Running with Ollama
Make sure Ollama is running locally:
```bash
ollama run llama3.2
```
Configure your `.env`:
```ini
LLM_PROVIDER=ollama
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=llama3.2
```

#### Running with Real Celesto MicroVMs
Supply your `CELESTO_API_KEY`:
```ini
CELESTO_API_KEY=your_key_here
SANDBOX_PROVIDER_MODE=auto
```
If `CELESTO_API_KEY` is omitted, MailGuard defaults to `DEMO_FALLBACK` mode (an isolated local subprocess runner).

### 2. Run Test Suite
```bash
.\.venv\Scripts\python.exe -m pytest -v backend/tests
```

### 3. Start FastAPI Server
```bash
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive API docs are available at `http://127.0.0.1:8000/docs`.

---

## API Endpoints

### Isolation & Attack Simulator
- `GET /api/celesto/status` — MicroVM isolation health and active provider mode.
- `GET /api/simulator/scenarios` — List 9 pre-loaded attack and benign simulation fixtures.
- `POST /api/simulator/trigger` — Trigger quarantine analysis with optional `run_llm_analysis: true` and `propose_actions: true`.

### Advisory Analysis (Phase 2B)
- `POST /api/analysis/{email_id}` — Trigger advisory LLM security analysis, urgency scoring (1–5), and calendar event extraction.
- `GET /api/analysis/{email_id}` — Retrieve the latest persisted advisory LLM analysis for a given email.

### Policy Engine & Human Approval (Phase 3)
- `GET /api/actions` — List all action proposals (supports optional `email_id` and `state` query filters).
- `GET /api/actions/{action_id}` — Retrieve full details and audit history for a single action proposal.
- `POST /api/actions/propose/{email_id}` — Run Policy Engine on an email to generate proposals in `PENDING_APPROVAL`.
- `POST /api/actions/{action_id}/approve` — Explicitly approve an action proposal (`PENDING_APPROVAL -> APPROVED`).
- `POST /api/actions/{action_id}/reject` — Explicitly reject an action proposal (`PENDING_APPROVAL -> REJECTED`).
- `POST /api/actions/{action_id}/execute` — Execute an `APPROVED` action proposal via safe simulated driver (`APPROVED -> EXECUTED`).
