# MailGuard — Session State & Checkpoint

---

## Project
**MailGuard** — Personal AI Communication Gatekeeper

---

## Current Phase
**Phase 2A** — Quarantine, Static Inspection & Attack Simulation

---

## Status
**Phase 2A implementation complete.** All 17 unit and integration tests passing.

---

## Completed in Phase 2A
- **FastAPI backend scaffold** with async lifespan and CORS.
- **`CelestoSandboxProvider` interface** defining the abstract quarantine and analysis contract.
- **`RealCelestoProvider`** implementing verified Celesto Cloud SDK (`Computer(provider="cloud", network_policy={"mode": "off"}, template_id="coding-agent")`).
- **`DemoFallbackProvider`** providing local environment-scrubbed subprocess isolation for zero-credential offline development.
- **`ProviderFactory`** resolving `auto`, `real`, or `demo` execution mode based on environment variables.
- **`inspector.py`** static analysis agent (pure Python standard library, zero guest dependencies) with Shannon entropy, brand typosquatting/homoglyph detection, zero-width unicode scanning, and regex signature extraction.
- **9 Deterministic attack/benign fixtures** (Normal, Interview, Assessment, Recruiter, Deadline, Newsletter, Phishing, Direct Prompt Injection, Hidden/Indirect Injection).
- **SQLite persistence layer** via SQLAlchemy async (`EmailRecord`, `CelestoTelemetryRecord`).
- **Simulator API** (`GET /api/simulator/scenarios`, `POST /api/simulator/trigger`).
- **Celesto telemetry API** (`GET /api/celesto/status`, `GET /api/celesto/telemetry`).
- **Security invariant tests** verifying size limits, schema rejection, and non-execution of prompt injections.
- **Inspector tests** verifying heuristics and accurate threat labeling.
- **Simulator tests** verifying end-to-end execution of all 9 scenarios.
- **Conditional real Celesto smoke test** verifying network lockdown and clean VM teardown when `CELESTO_API_KEY` is present.

---

## Test Results
```text
======================== 17 passed, 1 skipped in 8.81s ========================
```
* **Skipped Test:** `backend/tests/test_celesto_real_conditional.py::test_real_celesto_smoke`
* **Reason:** `CELESTO_API_KEY` is not yet configured in `.env`. The test cleanly skips and triggers fallback without failing.

---

## Current Active Mode
* **Active Isolation:** `DEMO_FALLBACK`
* **Sandbox ID Format:** `demo-subprocess-no-celesto-vm-<uuid>`
* **Real Celesto Status:** Implemented in [`real_celesto_provider.py`](file:///C:/Users/L13%20yoga/Downloads/celesto%20hackathon/backend/app/services/real_celesto_provider.py) but not yet live-tested with an active `CELESTO_API_KEY`.

---

## Unresolved Issues & Observations
1. **Celesto PyPI Distribution on Windows:**
   * The `celesto==0.1.4` package relies on `celesto-core~=2026.9.22`, which has pre-built wheels on PyPI for Linux (`manylinux_x86_64`) and macOS, but lacks a pre-compiled Windows wheel.
   * Compiling `celesto-core` on native Windows requires MSVC C++ build tools (`link.exe`).
   * **Workarounds Available:**
     - Run under WSL2 Ubuntu (installed on this host and verified compatible).
     - Or use Celesto Cloud directly once `CELESTO_API_KEY` is provisioned.
     - Or continue using `DemoFallbackProvider` for offline development.
2. **Celesto Cloud Credentials:**
   * Needs a valid key in `.env` (`CELESTO_API_KEY=...`) to execute live microVM smoke tests against Celesto Cloud.

---

## Next Phase: Phase 2B (DO NOT START AUTOMATICALLY)
**Phase 2B — LLM Security Analysis & Urgency/Event Classification**

### Phase 2B Planned Work:
- Pluggable LLM interface adapter (`Ollama`, `Gemini`, `OpenAI`, `MockLLM`).
- Local Ollama model support (`llama3.2`, `qwen2.5`) with offline mock fallback.
- Strict prompt/data separation using XML fencing (`<untrusted_email_body>`).
- Structured JSON output schemas for threat classification and urgency ratings (1–5).
- Calendar event extraction (date, time, title, organizer).
- Zero tool execution privileges for LLM.

---

## Important Security Invariants
- The LLM has **zero tools** and cannot execute actions or external APIs.
- The Policy Engine deterministically halts any external side effect until human approval is granted.
- Raw sandbox `stdout`/`stderr` is never passed directly to the LLM (must be validated via Pydantic first).
- The Demo Fallback mode must never be presented as real Celesto virtualization.
- Untrusted email content remains untrusted throughout the entire pipeline.

---

## Service Start Command
```powershell
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive API documentation: `http://127.0.0.1:8000/docs`
