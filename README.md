# MailGuard

**MailGuard** is a security-first personal AI communication gatekeeper with isolated Celesto sandbox quarantine.

## Architecture & Security Invariants
- **Security Invariant:** Authorization is deterministic and human-gated. No LLM output can directly authorize or execute an external side effect.
- **The Policy Engine:** Rejects any execution request that does not originate from an `APPROVED` action record. Enforced by state machine and tested explicitly.
- **Quarantine Boundary:** Untrusted email bytes are isolated in a sandbox with network egress strictly locked (`network_policy={"mode": "off"}`).
- **LLM Boundary:** The LLM has zero tools and acts purely as an advisory evaluator on sanitized, XML-fenced data.

## Running MailGuard

### 1. Environment Configuration
Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
To run in `REAL_CELESTO` mode with live microVMs, supply your `CELESTO_API_KEY`:
```ini
CELESTO_API_KEY=your_key_here
SANDBOX_PROVIDER_MODE=auto
```
If `CELESTO_API_KEY` is omitted, MailGuard automatically runs in `DEMO_FALLBACK` mode (using an isolated local subprocess for safe, zero-credential development).

### 2. Run Test Suite
```bash
.\.venv\Scripts\python.exe -m pytest -v backend/tests
```

### 3. Start FastAPI Server
```bash
.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
```
Interactive API docs are available at `http://127.0.0.1:8000/docs`.
