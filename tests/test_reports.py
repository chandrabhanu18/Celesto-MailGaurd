import re
import json
import math
from pathlib import Path
import pytest
import httpx

from backend.app.main import app
from backend.app.db.database import init_db

REPO_ROOT = Path(__file__).resolve().parent.parent
SANDBOX_REGEX = re.compile(r"^sbx-[a-z0-9]{8,}$")
ALLOWED_CAPABILITY_IDS = {
    "persistence", "snapshots", "celestofs", "browser", "published_ports",
    "network_policy", "safety_hooks", "host_mounts", "coding_agent_preset",
    "agentor_durable", "NOT_VERIFIED"
}

@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()



# -----------------------------------------------------------------------------
# 1. Health & Run Ledger API Contracts
# -----------------------------------------------------------------------------
@pytest.mark.asyncio
async def test_health_endpoint():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/health")
        assert resp.status_code == 200
        assert resp.json() == {"status": "ok"}


@pytest.mark.asyncio
async def test_runs_ledger_api_endpoints():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. GET /api/runs returns 200 and a list containing sbx-seeddemo1
        get_resp = await client.get("/api/runs")
        assert get_resp.status_code == 200
        runs_list = get_resp.json()
        assert isinstance(runs_list, list)
        seed_names = [r["sandbox_name"] for r in runs_list]
        assert "sbx-seeddemo1" in seed_names

        # 2. POST /api/runs with valid data returns 201
        valid_payload = {
            "run_id": "run-test-valid-01",
            "sandbox_name": "sbx-testalpha01",
            "problem_id": "prob-test-quarantine",
            "state": "running",
            "execution_target": "celesto_sandbox",
        }
        post_resp = await client.post("/api/runs", json=valid_payload)
        assert post_resp.status_code == 201
        saved = post_resp.json()
        assert saved["sandbox_name"] == "sbx-testalpha01"
        assert saved["execution_target"] == "celesto_sandbox"

        # 3. POST /api/runs with invalid execution_target returns 400
        bad_target_payload = {
            "run_id": "run-test-bad-target",
            "sandbox_name": "sbx-testalpha02",
            "problem_id": "prob-test-quarantine",
            "state": "running",
            "execution_target": "host",
        }
        res_bad_target = await client.post("/api/runs", json=bad_target_payload)
        assert res_bad_target.status_code == 400

        # 4. POST /api/runs with invalid sandbox_name returns 400
        bad_name_payload = {
            "run_id": "run-test-bad-name",
            "sandbox_name": "invalid-name!",
            "problem_id": "prob-test-quarantine",
            "state": "running",
            "execution_target": "celesto_sandbox",
        }
        res_bad_name = await client.post("/api/runs", json=bad_name_payload)
        assert res_bad_name.status_code == 400

        # 5. POST /api/runs with unknown state returns 400
        bad_state_payload = {
            "run_id": "run-test-bad-state",
            "sandbox_name": "sbx-testalpha03",
            "problem_id": "prob-test-quarantine",
            "state": "unknown_state_xyz",
            "execution_target": "celesto_sandbox",
        }
        res_bad_state = await client.post("/api/runs", json=bad_state_payload)
        assert res_bad_state.status_code == 400


# -----------------------------------------------------------------------------
# 2. Problem Statement Report (reports/problem.json)
# -----------------------------------------------------------------------------
def test_problem_report():
    file_path = REPO_ROOT / "reports" / "problem.json"
    assert file_path.exists(), "reports/problem.json must exist"
    data = json.loads(file_path.read_text(encoding="utf-8"))

    assert "who" in data and len(data["who"]) >= 40
    assert "agent_work" in data and len(data["agent_work"]) >= 40
    assert "proof_output" in data and len(data["proof_output"]) >= 20
    assert data.get("idea_source") in ("idea_bank", "original")


# -----------------------------------------------------------------------------
# 3. Capabilities Report (reports/capabilities.json)
# -----------------------------------------------------------------------------
def test_capabilities_report():
    file_path = REPO_ROOT / "reports" / "capabilities.json"
    assert file_path.exists(), "reports/capabilities.json must exist"
    data = json.loads(file_path.read_text(encoding="utf-8"))

    caps = data.get("capabilities", [])
    assert len(caps) >= 2, "Must contain at least 2 capabilities"

    ids = [c["id"] for c in caps]
    assert len(ids) == len(set(ids)), "Capability IDs must be unique"

    for c in caps:
        assert c["id"] in ALLOWED_CAPABILITY_IDS, f"Capability ID '{c['id']}' not in allowed set"
        assert len(c["why"]) >= 80, f"Capability why must be >= 80 chars for {c['id']}"
        ev_path = REPO_ROOT / c["evidence_path"]
        assert ev_path.exists(), f"evidence_path does not exist: {c['evidence_path']}"


# -----------------------------------------------------------------------------
# 4. Lifecycle Report (reports/lifecycle.json)
# -----------------------------------------------------------------------------
def test_lifecycle_report():
    file_path = REPO_ROOT / "reports" / "lifecycle.json"
    assert file_path.exists(), "reports/lifecycle.json must exist"
    data = json.loads(file_path.read_text(encoding="utf-8"))

    assert data.get("cleanup_on_success") is True
    assert data.get("cleanup_on_failure") is True
    assert data.get("cleanup_on_interrupt") is True

    names = data.get("sandbox_names", [])
    assert len(names) >= 1, "sandbox_names must not be empty"
    assert len(names) == len(set(names)), "sandbox_names must be unique"

    # Cross-reference with commands log or reliability file
    cmd_log = (REPO_ROOT / "logs" / "commands.jsonl").read_text(encoding="utf-8") if (REPO_ROOT / "logs" / "commands.jsonl").exists() else ""
    rel_path = REPO_ROOT / "reports" / "reliability.json"
    rel_data = json.loads(rel_path.read_text(encoding="utf-8")) if rel_path.exists() else {}
    rel_names = {r["sandbox_name"] for r in rel_data.get("runs", [])}

    for name in names:
        assert SANDBOX_REGEX.match(name), f"Sandbox name '{name}' does not match pattern"
        assert (name in cmd_log) or (name in rel_names), f"Sandbox name '{name}' not found in logs or reliability report"


# -----------------------------------------------------------------------------
# 5. Commands Audit Log (logs/commands.jsonl)
# -----------------------------------------------------------------------------
def test_commands_audit_log():
    log_file = REPO_ROOT / "logs" / "commands.jsonl"
    assert log_file.exists(), "logs/commands.jsonl must exist"
    lines = [line.strip() for line in log_file.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert len(lines) >= 1, "logs/commands.jsonl must have at least one line"

    for line in lines:
        entry = json.loads(line)
        assert "ts" in entry and isinstance(entry["ts"], str) and len(entry["ts"]) > 0
        assert SANDBOX_REGEX.match(entry["sandbox_name"]), f"Invalid sandbox name: {entry['sandbox_name']}"
        assert "command" in entry and len(entry["command"]) > 0
        assert entry["decision"] in ("allow", "block")
        assert entry["execution_target"] == "celesto_sandbox", "execution_target must equal celesto_sandbox"


# -----------------------------------------------------------------------------
# 6. Reliability Evaluation Report (reports/reliability.json & postmortem.md)
# -----------------------------------------------------------------------------
def test_reliability_report_and_math():
    rel_file = REPO_ROOT / "reports" / "reliability.json"
    assert rel_file.exists(), "reports/reliability.json must exist"
    data = json.loads(rel_file.read_text(encoding="utf-8"))

    runs = data.get("runs", [])
    run_count = data.get("run_count")
    assert run_count >= 20, "run_count must be at least 20"
    assert len(runs) == run_count, "run_count must equal len(runs)"

    names = [r["sandbox_name"] for r in runs]
    assert len(names) == len(set(names)), "Sandbox names must be unique"

    for r in runs:
        assert r["fresh"] is True
        assert isinstance(r["success"], bool)
        assert r["wall_clock_s"] >= 0
        assert r["boot_to_ready_s"] >= 0
        assert r["cost_usd"] >= 0
        assert SANDBOX_REGEX.match(r["sandbox_name"])

    # Verify arithmetic
    computed_successes = sum(1 for r in runs if r["success"])
    computed_success_rate = computed_successes / run_count
    assert abs(data["success_rate"] - computed_success_rate) <= 0.001

    # Median wall_clock_s (mean of 10th and 11th values for 20 sorted rows)
    sorted_wall = sorted(r["wall_clock_s"] for r in runs)
    n = len(sorted_wall)
    computed_median_wall = (sorted_wall[n // 2 - 1] + sorted_wall[n // 2]) / 2.0
    assert abs(data["median_wall_clock_s"] - computed_median_wall) <= 0.001

    # P90 wall_clock_s (1-based rank ceil(0.90 * n))
    p90_rank = math.ceil(0.90 * n)
    computed_p90 = sorted_wall[p90_rank - 1]
    assert abs(data["p90_wall_clock_s"] - computed_p90) <= 0.001

    # Median boot_to_ready_s
    sorted_boot = sorted(r["boot_to_ready_s"] for r in runs)
    computed_median_boot = (sorted_boot[n // 2 - 1] + sorted_boot[n // 2]) / 2.0
    assert abs(data["median_boot_to_ready_s"] - computed_median_boot) <= 0.001

    # Total cost USD
    computed_cost = sum(r["cost_usd"] for r in runs)
    assert abs(data["total_cost_usd"] - computed_cost) <= 0.01

    # Postmortem path
    pm_path = REPO_ROOT / data["postmortem_path"]
    assert pm_path.exists(), f"postmortem_path does not exist: {data['postmortem_path']}"
    assert len(pm_path.read_text(encoding="utf-8")) >= 200, "postmortem must be at least 200 characters"


# -----------------------------------------------------------------------------
# 7. Containment Test Report (reports/containment.json)
# -----------------------------------------------------------------------------
def test_containment_report():
    c_file = REPO_ROOT / "reports" / "containment.json"
    assert c_file.exists(), "reports/containment.json must exist"
    data = json.loads(c_file.read_text(encoding="utf-8"))

    assert data.get("attack") in ("prompt_injection_exfil", "destructive_command", "suspicious_package")
    assert data.get("blocked") is True
    assert data.get("host_untouched") is True

    ev_paths = data.get("evidence_paths", [])
    assert len(ev_paths) >= 1
    for p in ev_paths:
        full_path = REPO_ROOT / p
        assert full_path.exists(), f"Containment evidence path does not exist: {p}"


# -----------------------------------------------------------------------------
# 8. Failure Policy Report (reports/failure_policy.json & failure_trace.jsonl)
# -----------------------------------------------------------------------------
def test_failure_policy_report():
    fp_file = REPO_ROOT / "reports" / "failure_policy.json"
    assert fp_file.exists(), "reports/failure_policy.json must exist"
    data = json.loads(fp_file.read_text(encoding="utf-8"))

    assert data.get("failed_step") == 7
    assert data.get("total_steps") == 10
    policy = data.get("policy")
    assert policy in ("resume", "rollback", "fresh")
    assert len(data.get("rationale", "")) >= 200

    trace_path = REPO_ROOT / data.get("trace_path", "")
    assert trace_path.exists(), f"trace_path does not exist: {data.get('trace_path')}"
    lines = [json.loads(l) for l in trace_path.read_text(encoding="utf-8").splitlines() if l.strip()]

    # Verify matching policy_applied event
    policy_applied_events = [l for l in lines if l.get("event") == "policy_applied" and l.get("policy") == policy]
    assert len(policy_applied_events) >= 1, f"Did not find event 'policy_applied' with policy '{policy}' in trace"


# -----------------------------------------------------------------------------
# 9. Concurrency Report (reports/concurrency.json)
# -----------------------------------------------------------------------------
def test_concurrency_report():
    conc_file = REPO_ROOT / "reports" / "concurrency.json"
    assert conc_file.exists(), "reports/concurrency.json must exist"
    data = json.loads(conc_file.read_text(encoding="utf-8"))

    jobs = data.get("jobs", [])
    assert len(jobs) >= 5, "Must record at least 5 concurrent jobs"

    names = [j["sandbox_name"] for j in jobs]
    assert len(names) == len(set(names)), "Concurrent job sandbox names must be unique"
    for j in jobs:
        assert SANDBOX_REGEX.match(j["sandbox_name"])
        assert "started_at" in j and len(j["started_at"]) > 0

    assert len(data.get("breakage_notes", "")) >= 40


# -----------------------------------------------------------------------------
# 10. README Required Phrases Check
# -----------------------------------------------------------------------------
def test_readme_required_phrases():
    readme_file = REPO_ROOT / "README.md"
    assert readme_file.exists(), "README.md must exist at repository root"
    content = readme_file.read_text(encoding="utf-8")

    required_phrases = [
        "Problem statement",
        "How I used Celesto",
        "Eval report",
        "Containment test",
        "State and failure design",
        "Setup",
    ]
    for phrase in required_phrases:
        assert phrase in content, f"README.md missing required phrase: '{phrase}'"


# -----------------------------------------------------------------------------
# 11. Environment Security Check (.env.example)
# -----------------------------------------------------------------------------
def test_env_example_and_security():
    example_file = REPO_ROOT / ".env.example"
    assert example_file.exists(), ".env.example must exist"
    example_content = example_file.read_text(encoding="utf-8")

    required_keys = [
        "CELESTO_PROVIDER",
        "CELESTO_API_KEY",
        "LLM_API_KEY",
        "LLM_MODEL",
        "DATABASE_URL",
        "API_PORT",
    ]
    for key in required_keys:
        assert key in example_content, f".env.example missing required key: '{key}'"


# -----------------------------------------------------------------------------
# 12. Docker Compose & Postgres Seeds Check
# -----------------------------------------------------------------------------
def test_docker_compose_and_seeds():
    compose_file = REPO_ROOT / "docker-compose.yml"
    assert compose_file.exists(), "docker-compose.yml must exist"
    compose_content = compose_file.read_text(encoding="utf-8")
    assert "api:" in compose_content
    assert "ledger:" in compose_content
    assert "pg_isready" in compose_content
    assert "/health" in compose_content

    seed_file = REPO_ROOT / "seeds" / "01_runs.sql"
    assert seed_file.exists(), "seeds/01_runs.sql must exist"
    seed_content = seed_file.read_text(encoding="utf-8")
    assert "sbx-seeddemo1" in seed_content
    assert "celesto_sandbox" in seed_content
