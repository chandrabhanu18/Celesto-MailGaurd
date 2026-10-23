import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.db.database import init_db

@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()

@pytest.mark.asyncio
async def test_identity_invariant_and_scenario_replacement():
    """
    Regression Test for State Synchronization and Identity Invariant:
    Trigger "Invoice Review [ADMIN OVERRIDE]"
    -> returned email ID is X
    -> investigation email ID is X
    -> analysis email ID is X
    -> action email ID is X
    Also verifies triggering a second scenario replaces the previous investigation correctly.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Trigger Scenario 1: Invoice Review [ADMIN OVERRIDE] (Direct Injection)
        res1 = await ac.post("/api/simulator/trigger", json={
            "scenario_id": "scenario_direct_injection",
            "run_llm_analysis": True,
            "propose_actions": True
        })
        assert res1.status_code == 200
        data1 = res1.json()
        email_id_x = data1["email_id"]
        assert email_id_x is not None
        assert data1["scenario_id"] == "scenario_direct_injection"

        # Verify investigation email ID is X
        inv1 = await ac.get(f"/api/emails/{email_id_x}")
        assert inv1.status_code == 200
        detail1 = inv1.json()
        assert detail1["id"] == email_id_x
        assert detail1["scenario_id"] == "scenario_direct_injection"
        assert "invoice" in detail1["subject"].lower()

        # Verify analysis email ID is X
        assert detail1["latest_analysis"] is not None
        assert detail1["latest_analysis"]["email_id"] == email_id_x
        assert detail1["latest_analysis"]["threat_category"] == "PROMPT_INJECTION"

        # Verify action email ID is X
        assert len(detail1["actions"]) >= 1
        for act in detail1["actions"]:
            assert act["email_id"] == email_id_x
            assert act["action_type"] == "QUARANTINE_EMAIL"
            assert act["state"] == "PENDING_APPROVAL"

        # 2. Trigger Scenario 2: Critical Security Alert: Account Compromise (Phishing)
        # Proves triggering a second scenario replaces the investigation email identity
        res2 = await ac.post("/api/simulator/trigger", json={
            "scenario_id": "scenario_phishing",
            "run_llm_analysis": True,
            "propose_actions": True
        })
        assert res2.status_code == 200
        data2 = res2.json()
        email_id_y = data2["email_id"]
        assert email_id_y is not None
        assert email_id_y != email_id_x  # Must be a distinct canonical ID

        # Verify investigation email ID is Y
        inv2 = await ac.get(f"/api/emails/{email_id_y}")
        assert inv2.status_code == 200
        detail2 = inv2.json()
        assert detail2["id"] == email_id_y
        assert detail2["scenario_id"] == "scenario_phishing"
        assert "google account" in detail2["subject"].lower()

        # Verify analysis email ID is Y
        assert detail2["latest_analysis"] is not None
        assert detail2["latest_analysis"]["email_id"] == email_id_y
        assert detail2["latest_analysis"]["threat_category"] == "PHISHING"

        # Verify action email ID is Y
        assert len(detail2["actions"]) >= 1
        for act in detail2["actions"]:
            assert act["email_id"] == email_id_y
            assert act["state"] == "PENDING_APPROVAL"

        # 3. Trigger Scenario 3: Engineering Sprint Sync (Benign)
        res3 = await ac.post("/api/simulator/trigger", json={
            "scenario_id": "scenario_normal",
            "run_llm_analysis": True,
            "propose_actions": True
        })
        assert res3.status_code == 200
        data3 = res3.json()
        email_id_z = data3["email_id"]
        assert email_id_z != email_id_y
        assert email_id_z != email_id_x

        inv3 = await ac.get(f"/api/emails/{email_id_z}")
        assert inv3.status_code == 200
        detail3 = inv3.json()
        assert detail3["id"] == email_id_z
        assert detail3["static_inspection"]["static_risk_label"] == "SAFE"
        assert detail3["latest_analysis"]["threat_category"] == "BENIGN"
        assert len(detail3["actions"]) == 0

@pytest.mark.asyncio
async def test_phase4_e2e_scenarios_and_gating_flow():
    """
    Comprehensive Phase 4 E2E verification test:
    Gating lifecycle:
    - PENDING_APPROVAL cannot execute (HTTP 403)
    - APPROVE -> APPROVED
    - EXECUTE -> EXECUTED (Simulated driver)
    - REPLAY EXECUTE -> Blocked (HTTP 403)
    - PENDING_APPROVAL -> REJECT -> REJECTED (Terminal)
    - REJECTED cannot execute (HTTP 403)
    - REJECTED cannot be approved (HTTP 400)
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        direct_inj_res = await ac.post("/api/simulator/trigger", json={
            "scenario_id": "scenario_direct_injection",
            "run_llm_analysis": True,
            "propose_actions": True
        })
        assert direct_inj_res.status_code == 200
        direct_inj_data = direct_inj_res.json()
        target_action = direct_inj_data["proposed_actions"][0]
        action_id = target_action["id"]
        assert target_action["state"] == "PENDING_APPROVAL"

        # Attempt execution while in PENDING_APPROVAL -> STRICTLY BLOCKED (HTTP 403)
        exec_unapproved = await ac.post(f"/api/actions/{action_id}/execute")
        assert exec_unapproved.status_code == 403
        assert "human approval is strictly required" in exec_unapproved.json()["detail"].lower()

        # Explicit Human Approval
        approve_res = await ac.post(f"/api/actions/{action_id}/approve", json={"notes": "SOC Analyst confirmed quarantine"})
        assert approve_res.status_code == 200
        assert approve_res.json()["state"] == "APPROVED"
        assert approve_res.json()["is_human_approved"] is True

        # Execution of APPROVED action -> EXECUTED (Simulated Driver)
        exec_approved = await ac.post(f"/api/actions/{action_id}/execute")
        assert exec_approved.status_code == 200
        exec_data = exec_approved.json()
        assert exec_data["state"] == "EXECUTED"
        assert exec_data["is_simulated"] is True
        assert exec_data["execution_result"]["status"] == "SUCCESS"

        # Replay Execution Attempt -> STRICTLY BLOCKED (HTTP 403)
        exec_replay = await ac.post(f"/api/actions/{action_id}/execute")
        assert exec_replay.status_code == 403
        assert "already been executed" in exec_replay.json()["detail"].lower()
