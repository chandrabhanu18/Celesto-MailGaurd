# MailGuard — Session State & Checkpoint

---

## Project
**MailGuard** — Personal AI Communication Gatekeeper

---

## Current Phase
**Phase 4** — Security Operations Console (Frontend UI & Read-Only Triage APIs)

---

## Status
**Phase 4 implementation complete.** All 62 unit and integration tests passing (1 conditional test skipped cleanly). Frontend compiles with 0 errors via `npm run build`.

---

## Completed in Phase 4

### 1. Backend Extensions (Strictly Read-Only, Gating Invariants Preserved)
- **Schemas (`backend/app/schemas/email.py`):**
  - `EmailListItem`: Summarized view of incoming emails with static risk label/score, threat indicators count, advisory AI classification (threat category, urgency, confidence), action proposal state, and quarantine flag.
  - `EmailDetailResponse`: Full investigation model providing sanitized text, Phase 2A static indicators & telemetry, Phase 2B advisory LLM analysis, and Phase 3 action proposals.
- **Endpoints (`backend/app/api/emails.py`):**
  - `GET /api/emails`: Read-only queue listing with optional limit.
  - `GET /api/emails/{email_id}`: Read-only deep-dive investigation record.
  - Strict method restrictions: rejects POST/PUT/DELETE.
- **CORS Hardening (`backend/app/main.py`):**
  - Replaced wildcard `*` with explicit development origins: `http://localhost:5173`, `http://127.0.0.1:5173`.
  - Mounted `/api/emails` router.
- **Backend Tests (`backend/tests/test_emails_api.py`, `backend/tests/test_phase4_console_flow.py`):**
  - Added 5 new tests verifying read-only email endpoints and full Phase 4 E2E lifecycle (Benign, Phishing, Direct Injection, Zero-Width Injection, Approval -> Gated Execution -> Replay Blocking, Rejection -> Terminal state).

### 2. Frontend Security Operations Console (`frontend/`)
- Built with React 19 + TypeScript + Vite + Tailwind CSS + Lucide Icons.
- **Header (`Header.tsx`):**
  - Persistent status indicators for Celesto Isolation (`DEMO FALLBACK` with clear `SUBPROCESS SIMULATION` label vs `REAL CELESTO`), Advisory LLM (`MOCK / ZERO TOOLS`), Policy Engine (`DETERMINISTIC`), Execution Mode (`SIMULATED ONLY`), and Human Gate (`MANDATORY`).
- **Security KPI Strip (`KpiMetrics.tsx`):**
  - Metrics derived strictly from backend records: Emails Analyzed, Threats Detected, Pending Approvals, Simulated Executions, Critical Threat Level, and Quarantined Items.
- **Scenario Launcher (`ScenarioLauncher.tsx`):**
  - Triggers all 9 existing backend fixtures through `POST /api/simulator/trigger` with options for Phase 2B advisory analysis and Phase 3 action gating.
- **Email Threat Queue (`EmailQueue.tsx`):**
  - High-density list with severity badges (`CRITICAL`, `HIGH RISK`, `MEDIUM`, `LOW`, `SAFE`), urgency badges (1–5), confidence scores, and action state pills (`PENDING_APPROVAL`, `APPROVED`, `EXECUTED`, `REJECTED`, `FAILED`).
- **Investigation Panel (`InvestigationPanel.tsx`):**
  - Section 1: Email envelope and sanitized text fenced in `<untrusted_email_body>` with active content stripped notice.
  - Section 2: Phase 2A static inspection heuristics and Celesto microVM execution telemetry.
  - Section 3: Phase 2B advisory LLM evaluation prominently labeled: *"ADVISORY ONLY — AI analysis is probabilistic and does not authorize actions."*
  - Section 4: Phase 3 deterministic policy decision and embedded action control.
- **Action Control Card (`ActionControlCard.tsx`):**
  - Clearly separated under *"DETERMINISTIC GATEKEEPER — Policy engine, not the LLM, determines the executable proposal."*
  - `PENDING_APPROVAL`: Approve and Reject buttons enabled; Execute button disabled with *"Execution locked — explicit human approval required."*
  - `APPROVED`: Execute button enabled for simulated driver.
  - `REJECTED`: Terminal state display with mandatory human rejection reason.
  - `EXECUTED`: Watermarked with *"SIMULATED EXECUTION — No live Gmail, Calendar, or Social APIs were contacted."*
  - Replay protection: Attempting duplicate execution is prohibited.
- **Telemetry Drawer (`TelemetryDrawer.tsx`):**
  - Slide-over viewing raw sandbox execution events from `GET /api/celesto/telemetry` with clear differentiation between `REAL_CELESTO` and `DEMO_FALLBACK`.
- **API Client (`api.ts`):**
  - Centralized, typed API layer strictly mirroring backend Pydantic models.

---

## Test Results
```text
======================== 63 passed, 1 skipped in 14.78s ========================
```
* **Phase 4 Tests:** 6 / 6 passed ([`backend/tests/test_phase4_console_flow.py`](file:///C:/Users/L13%20yoga/Downloads/celesto%20hackathon/backend/tests/test_phase4_console_flow.py), [`backend/tests/test_emails_api.py`](file:///C:/Users/L13%20yoga/Downloads/celesto%20hackathon/backend/tests/test_emails_api.py))
* **Frontend Build:** `npm run build` completed in ~1.5s with 0 errors.
* **Scenario Synchronization & Identity Invariant:** Verified across `Invoice Review [ADMIN OVERRIDE]`, `Critical Security Alert: Account Compromise`, and `Engineering Sprint Sync`.

---

## Service Commands
1. Start backend:
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
2. Start frontend:
```powershell
cd frontend
npm run dev
```
Interactive Console: `http://localhost:5173`
Interactive API Docs: `http://127.0.0.1:8000/docs`
