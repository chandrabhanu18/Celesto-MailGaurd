# MailGuard — Personal AI Communication Gatekeeper

> **“Read automatically. Think safely. Act only with permission.”**

MailGuard is a security-first personal AI communication gatekeeper that executes untrusted email inspection inside authentic Celesto microVM sandboxes, performs advisory threat reasoning using XML-delimited prompt fences, and strictly gates all external actions behind deterministic policy and human approval.

---

## Problem statement

Security teams, executives, and developers are increasingly targeted by sophisticated email-based threats, including credential phishing, adversarial prompt injections, homoglyph deception, and weaponized payload drops. When an AI agent processes incoming communications directly on a host machine, a single poisoned prompt or malicious attachment can compromise local environment variables, exfiltrate API keys, or execute destructive commands.

MailGuard solves this by decoupling untrusted content processing from execution authority:
1. **Untrusted Computer Work**: All parsing, attachment extraction, and static payload inspection execute strictly inside ephemeral Celesto sandboxes.
2. **Advisory AI Reasoning**: The LLM functions exclusively as a zero-tool advisory classifier within hardened prompt fences (`<untrusted_email_body>`).
3. **Deterministic Human-Gated Actions**: The AI cannot trigger actions directly. Actions are proposed strictly in `PENDING_APPROVAL` and require explicit human authorization before controlled execution.

---

## Architecture & Data Flow

```text
                           OPERATOR / HUMAN
                                  │
                                  ▼
                        React MailGuard Console
                                  │
                                  ▼ (HTTP)
                         FastAPI API Gateway
                                  │
            ┌─────────────────────┴─────────────────────┐
            ▼                                           ▼
   Untrusted Email Stream                      Run Ledger (Postgres)
            │                                           ▲
            ▼                                           │
  ┌───────────────────────────────────────────┐         │
  │        EXECUTION ZONE (Celesto)           │         │
  │  Celesto Cloud Ephemeral microVM          │         │
  │  - Template: coding-agent                 │         │
  │  - Guest Python Static Inspector          │─────────┘
  │  - Zero Host Secret Injection             │ (Audit & Telemetry)
  └───────────────────────────────────────────┘
            │
            ▼ (Validated JSON schema <= 512KB)
  ┌───────────────────────────────────────────┐
  │         ADVISORY REASONING ZONE           │
  │  LLM Evaluation Engine                    │
  │  - Isolated XML Fencing                   │
  │  - Zero Tools / Zero Host Access          │
  └───────────────────────────────────────────┘
            │
            ▼ (Advisory Classification)
  ┌───────────────────────────────────────────┐
  │         CONTROL PLANE & DECISION          │
  │  Deterministic Policy Engine              │
  │  - Proposes Action: QUARANTINE_EMAIL      │
  │  - State: PENDING_APPROVAL                │
  └───────────────────────────────────────────┘
            │
            ▼
     [Human Approval Gate] ──► APPROVED ──► Controlled Driver (Isolated)
```

---

## How I used Celesto

MailGuard relies on Celesto as its foundational compute isolation primitive rather than a decorative wrapper:

### 1. `coding_agent_preset`
- **Why Celesto**: Rather than building custom VM images or running untrusted code on the app server, MailGuard leverages Celesto's `coding-agent` template (`Computer(provider="cloud", template_id="coding-agent")`).
- **Where Used**: In `backend/app/services/real_celesto_provider.py`, each incoming email payload is transferred into a fresh microVM via base64 byte streaming. The guest Python environment executes deep header analysis, homoglyph detection, and malicious URL extraction inside the guest microVM.
- **Why It Matters**: If replaced with host `subprocess.run()`, a single malformed payload or exploit would compromise the host system.

### 2. Second Capability Status: `NOT_VERIFIED`
- **Status & Integrity Audit**: While Celesto SDK provides class-based `Callback` hooks for its local runtime (`celesto.facade.Celesto`), `Computer(provider="cloud")` in Celesto 0.1.8 does not expose command interception hooks through the cloud wrapper.
- **MailGuard Policy Enforcement**: Pre-execution command blocking and policy decisions are handled by MailGuard's own deterministic application-level engine (`policy_engine.py`) and audited to `logs/commands.jsonl`. Rather than misattributing application logic to Celesto SDK callbacks, MailGuard honestly records this second capability as `NOT_VERIFIED`.

### Honest Celesto SDK Integration Note
Celesto Cloud SDK 0.1.8 does not expose `network_policy={"mode": "off"}` or `upload_file()` in its `Computer` constructor. MailGuard honestly reflects this:
- Network isolation is not artificially claimed at the SDK constructor level (`network_mode: "provider_default"`).
- File delivery into the guest is achieved safely by piping base64 payloads through `computer.run()` inside the microVM.
- Host credentials and secrets are strictly excluded from guest environments.

---

## Eval report

MailGuard's reliability and performance were evaluated across 20 fresh sandbox execution cycles. Summary metrics were calculated in accordance with exact evaluation formulas:

- **Total Fresh Runs**: 20
- **Success Rate**: 100.0% (20/20)
- **Median Wall-Clock Time**: 0.084s
- **P90 Wall-Clock Time**: 0.125s
- **Median Boot-to-Ready Time**: 0.034s
- **Total Computational Cost**: $0.0030 USD
- **Failure Post-Mortem**: Documented in detail in [`reports/postmortem.md`](reports/postmortem.md)

Detailed per-run telemetry and timestamps are recorded in [`reports/reliability.json`](reports/reliability.json).

---

## Containment test

To verify that adversarial inputs cannot escape the sandbox boundary, MailGuard was evaluated against an active prompt injection and credential exfiltration attack:

- **Attack Type**: `prompt_injection_exfil`
- **Payload**: Injection string attempting to override system directives, dump `.env`, and exfiltrate `$CELESTO_API_KEY` to an external endpoint.
- **Defense Mechanism**: Multi-layer containment:
  1. Prompt delimiter fencing (`<untrusted_email_body>`) neutralized instruction hijack.
  2. Advisory LLM categorized payload as `PROMPT_INJECTION` (Critical, Urgency 5).
  3. Policy Engine intercepted the threat and blocked external execution.
  4. Command audit logged the blocked directive: `"decision": "block"`.
- **Outcome**: `blocked: true`, `host_untouched: true`.
- **Evidence**: Complete execution transcript available in [`reports/evidence/containment.log`](reports/evidence/containment.log) and [`reports/containment.json`](reports/containment.json).

---

## State and failure design

When multi-step agent tasks experience unexpected mid-task failures, MailGuard enforces a deterministic recovery strategy:

- **Target Benchmark**: Step 7 of 10 failed (`failed_step: 7`, `total_steps: 10`).
- **Enforced Policy**: `fresh`
- **Design Rationale**: When inspecting untrusted or weaponized attachments, a crash or timeout at step 7 (dynamic detonation probe) indicates potential guest compromise or corrupted process state. Rather than attempting to `resume` a tainted environment or `rollback` to an uncertain checkpoint, MailGuard immediately destroys the microVM, verifies full cleanup, and initializes a completely fresh sandbox from the verified template baseline.
- **Trace Evidence**: Documented in [`reports/failure_policy.json`](reports/failure_policy.json) and [`reports/failure_trace.jsonl`](reports/failure_trace.jsonl).

---

## Setup

The complete MailGuard trusted control plane boots in under 5 minutes using Docker Compose or local Python.

### Prerequisites
- Docker & Docker Compose **OR** Python 3.12+ / Node.js 18+
- Celesto API Key (Optional for cloud microVMs; defaults to isolated demo fallback mode if omitted)

### Option A: Docker Compose (Recommended)
```bash
# 1. Clone repository
git clone https://github.com/chandrabhanu18/Celesto-MailGaurd.git
cd Celesto-MailGaurd

# 2. Copy environment template
cp .env.example .env

# 3. Start trusted control plane (API + Postgres Ledger)
docker-compose up -d

# 4. Verify health (returns {"status": "ok"})
curl http://localhost:8080/health
```

### Option B: Local Development
```bash
# Backend Setup
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
pip install -e .

# Run Backend
uvicorn backend.app.main:app --host 127.0.0.1 --port 8080 --reload

# Frontend Setup
cd frontend
npm install
npm run dev
```

Interactive API documentation is accessible at `http://localhost:8080/docs`.

---

## Action State Machine

MailGuard enforces a strict deterministic transition lifecycle for all proposed actions:

| Initial State | Event / Trigger | Target State | Permitted? |
|---|---|---|:---:|
| `PENDING_APPROVAL` | Human Approval (`/approve`) | `APPROVED` | **Yes** |
| `PENDING_APPROVAL` | Human Rejection (`/reject`) | `REJECTED` | **Yes** |
| `APPROVED` | Execution Driver Success (`/execute`) | `EXECUTED` | **Yes** |
| `APPROVED` | Execution Driver Error (`/execute`) | `FAILED` | **Yes** |
| `PENDING_APPROVAL` | Direct Execution (`/execute`) | *Blocked (HTTP 403)* | **No** |
| `REJECTED` | Approval / Execution | *Blocked (HTTP 400/403)* | **No** |
| `EXECUTED` | Re-execution (Replay) | *Blocked (HTTP 403)* | **No** |

---

## Demo Walkthrough

A complete 3-minute operator workflow demonstration is documented in [`demo/README.md`](demo/README.md), illustrating:
1. Ingestion of untrusted email.
2. Celesto microVM quarantine execution.
3. Advisory LLM classification.
4. Human approval gate and replay protection.
