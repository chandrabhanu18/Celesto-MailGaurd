# MailGuard — 3-Minute Demo Walkthrough Guide

This document provides the recommended script and step-by-step operator flow for recording the MailGuard demonstration video.

---

## 3-Minute Demonstration Script

### Minute 1: The Threat & Problem (0:00 - 1:00)
1. **Introduction**:
   - Introduce MailGuard as an AI Communication Gatekeeper governed by:
     > *"Read automatically. Think safely. Act only with permission."*
2. **Untrusted Ingestion**:
   - In the MailGuard Web UI, open the **Scenario Launcher**.
   - Trigger the **PayPal Account Phishing** or **Prompt Injection** scenario.
   - Highlight that the email contains adversarial text attempting to steal credentials and override AI instructions.

### Minute 2: Celesto MicroVM Isolation & Advisory Analysis (1:00 - 2:00)
1. **Celesto MicroVM Quarantine**:
   - Show the **Provider Status**: `REAL CELESTO MICROVM` (or `DEMO_FALLBACK` for local offline dev).
   - Show the ephemeral sandbox identifier (`sbx-...`).
   - Explain that all parsing, header verification, homoglyph analysis, and attachment unpacking executed strictly inside the Celesto guest microVM, keeping the host untouched.
2. **Advisory LLM Reasoning**:
   - Show the **Investigation Panel**.
   - Review threat classification (`PHISHING` or `PROMPT_INJECTION`), confidence score, urgency rating (1–5), and threat indicators.
   - Emphasize that the LLM is **advisory only** with **zero tool execution capability**.

### Minute 3: Deterministic Policy, Human Approval & Replay Defense (2:00 - 3:00)
1. **Human-in-the-Loop Gate**:
   - Show that the deterministic Policy Engine proposed `QUARANTINE_EMAIL` in the `PENDING_APPROVAL` state.
   - Explain that the action is strictly halted until an explicit human operator reviews and clicks **Approve**.
2. **Controlled Execution**:
   - Click **Approve**.
   - Watch the state transition: `PENDING_APPROVAL ➔ APPROVED ➔ EXECUTED`.
3. **Replay Protection**:
   - Attempt to click or re-execute the action again.
   - Demonstrate that replay protection blocks duplicate execution (HTTP 403 Forbidden).
4. **Audit Trail**:
   - Open the **Run Ledger** / `logs/commands.jsonl` to show that every command and policy decision is permanently recorded.
