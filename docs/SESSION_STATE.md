# MailGuard — Session State & Checkpoint

---

## Project
**MailGuard** — Personal AI Communication Gatekeeper

---

## Current Phase
**Phase 3** — Policy Engine, Human Approval Workflow & Action Gating

---

## Status
**Phase 3 implementation complete.** All 57 unit and integration tests passing.

---

## Completed in Phase 3
- **Action Types & Deterministic State Machine (`backend/app/schemas/action.py`):**
  - Action types: `QUARANTINE_EMAIL`, `FLAG_EMAIL`, `CREATE_CALENDAR_EVENT`, `GENERATE_REPLY`, `PUBLISH_SOCIAL_CONTENT`.
  - State machine: `PENDING_APPROVAL`, `APPROVED`, `REJECTED`, `EXECUTED`, `FAILED`.
  - Strict transition constraints:
    - `PENDING_APPROVAL` ➔ `APPROVED` (via explicit human approval)
    - `PENDING_APPROVAL` ➔ `REJECTED` (terminal state with mandatory reason)
    - `APPROVED` ➔ `EXECUTED` (via simulated executor)
    - `APPROVED` ➔ `FAILED` (upon driver execution error)
    - All other transitions strictly forbidden (e.g. `PENDING_APPROVAL` cannot execute, `REJECTED` cannot approve or execute, replay execution is blocked).
- **Deterministic Policy Engine (`backend/app/services/policy_engine.py`):**
  - Consumes Phase 2A static inspection findings and Phase 2B advisory LLM assessments.
  - Implements deterministic rules (`PHISHING_OR_MALWARE_QUARANTINE`, `PROMPT_INJECTION_QUARANTINE`, `CALENDAR_EVENT_PROPOSAL`, `HIGH_URGENCY_FLAG`).
  - LLM recommendations are treated purely as advisory inputs; the Policy Engine deterministically decides which proposals to create.
  - All proposals are initialized strictly in `PENDING_APPROVAL` state with `is_human_approved=False`.
- **Human Approval Service (`backend/app/services/approval_service.py`):**
  - Enforces explicit human approval workflow (`approve_action`, `reject_action`).
  - Validates action state, prevents invalid transitions, and timestamps decisions.
- **Safe Simulated Action Executor (`backend/app/services/action_executor.py`):**
  - Hard authorization gating: verifies `action.state == APPROVED` before performing any operation.
  - Rejects `PENDING_APPROVAL` actions with `ActionAuthorizationError` (HTTP 403).
  - Prohibits duplicate/replay execution of `EXECUTED` actions.
  - Safe simulated drivers for quarantine isolation, mailbox tagging, calendar drafts, and reply drafts. Zero connection to live Gmail, Google Calendar, or social media APIs.
- **Database Persistence (`backend/app/db/models.py`):**
  - Added `ActionProposalRecord` table with relationships to `EmailRecord` and `LLMAnalysisRecord`.
  - Full audit trail: timestamps (`created_at`, `approved_at`, `rejected_at`, `executed_at`), `policy_rule`, `reason`, `risk_level`, `rejection_reason`, and `execution_result_json`.
- **API Endpoints (`backend/app/api/actions.py`):**
  - `GET /api/actions`: List action proposals (filterable by `email_id` and `state`).
  - `GET /api/actions/{action_id}`: Retrieve proposal details and audit history.
  - `POST /api/actions/propose/{email_id}`: Trigger Policy Engine for an email.
  - `POST /api/actions/{action_id}/approve`: Approve a `PENDING_APPROVAL` proposal.
  - `POST /api/actions/{action_id}/reject`: Reject a `PENDING_APPROVAL` proposal with reason.
  - `POST /api/actions/{action_id}/execute`: Execute an `APPROVED` proposal. Rejects `PENDING_APPROVAL` with HTTP 403.
- **Simulator Pipeline Integration (`backend/app/api/simulator.py`):**
  - Added optional `propose_actions: bool = False` flag to `SimulationTriggerRequest`.
  - When enabled, runs Phase 2A ➔ Phase 2B ➔ Policy Engine ➔ Action Proposal, stopping strictly at `PENDING_APPROVAL`.
- **Comprehensive Security Test Suite (`backend/tests/test_policy_and_actions.py`):**
  - 20 new tests verifying valid/invalid state transitions, replay blocking, unapproved execution prevention, policy rules, and adversarial email instructions.

---

## Test Results
```text
======================== 57 passed, 1 skipped in 8.82s ========================
```
* **Phase 3 Tests:** 20 / 20 passed ([`backend/tests/test_policy_and_actions.py`](file:///C:/Users/L13%20yoga/Downloads/celesto%20hackathon/backend/tests/test_policy_and_actions.py))
* **Phase 2B Tests:** 20 / 20 passed ([`backend/tests/test_llm_analysis.py`](file:///C:/Users/L13%20yoga/Downloads/celesto%20hackathon/backend/tests/test_llm_analysis.py))
* **Phase 2A Tests:** 17 / 17 passed (0 regressions)
* **Skipped Test:** [`backend/tests/test_celesto_real_conditional.py::test_real_celesto_smoke`](file:///C:/Users/L13%20yoga/Downloads/celesto%20hackathon/backend/tests/test_celesto_real_conditional.py) (cleanly skipped because `CELESTO_API_KEY` is not present in `.env`)

---

## Current Active Configuration
* **Active Celesto Isolation:** `DEMO_FALLBACK` (`demo-subprocess-no-celesto-vm-<uuid>`)
* **Active LLM Provider:** `mock` (`MockLLM`, model: `mock-deterministic-v1`)
* **Policy Engine:** Deterministic rule set active (`PHISHING_OR_MALWARE_QUARANTINE`, `PROMPT_INJECTION_QUARANTINE`, `CALENDAR_EVENT_PROPOSAL`, `HIGH_URGENCY_FLAG`)
* **Action Executor:** Safe simulated execution drivers active (no live Gmail/Calendar/Social connections)

---

## Action State Machine

```text
[Policy Engine] ➔ PENDING_APPROVAL
                       ├── (Human Approval) ➔ APPROVED ➔ (Executor) ➔ EXECUTED (or FAILED)
                       └── (Human Rejection) ➔ REJECTED (Terminal)
```

---

## Unresolved Issues & Observations
1. **Celesto Cloud API Key:** `CELESTO_API_KEY` is not configured in `.env`, so live microVM testing operates in transparent `DEMO_FALLBACK` mode.
2. **Celesto PyPI Package on Native Windows:** The upstream `celesto-core` C-extension lacks pre-built Windows wheels on PyPI (usable via WSL2 or Celesto Cloud).

---

## Next Phase: Phase 4 (DO NOT START AUTOMATICALLY)
**Phase 4 — Frontend Web Dashboard, Interactive Quarantine & Action Review Console**
- Interactive gatekeeper UI for reviewing emails, threat analysis, and urgency.
- Human approval queue interface for approving/rejecting proposals with one click.
- Execution history audit logs and telemetry visualizer.

---

## Service Start Command
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive API documentation: `http://127.0.0.1:8000/docs`
