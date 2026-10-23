import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.db.database import init_db

@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()

@pytest.mark.asyncio
async def test_get_emails_empty_or_list():
    """Verify GET /api/emails returns 200 and schema with total and emails list."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/emails")
        assert resp.status_code == 200
        data = resp.json()
        assert "emails" in data
        assert "total" in data
        assert isinstance(data["emails"], list)
        assert data["total"] == len(data["emails"])

@pytest.mark.asyncio
async def test_get_email_detail_not_found():
    """Verify GET /api/emails/{non_existent_id} returns 404."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/emails/non-existent-uuid-1234")
        assert resp.status_code == 404
        assert "not found" in resp.json()["detail"].lower()

@pytest.mark.asyncio
async def test_get_emails_and_detail_after_simulation():
    """Verify that after running a scenario, the email queue and detail endpoints expose all data accurately."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Trigger simulation with LLM analysis and action proposals
        sim_resp = await ac.post("/api/simulator/trigger", json={
            "scenario_id": "scenario_phishing",
            "run_llm_analysis": True,
            "propose_actions": True
        })
        assert sim_resp.status_code == 200
        sim_data = sim_resp.json()
        email_id = sim_data["email_id"]
        assert email_id is not None

        # 1. Test GET /api/emails list
        list_resp = await ac.get("/api/emails")
        assert list_resp.status_code == 200
        list_data = list_resp.json()
        assert list_data["total"] >= 1

        target_email = next((e for e in list_data["emails"] if e["id"] == email_id), None)
        assert target_email is not None
        assert target_email["scenario_id"] == "scenario_phishing"
        assert target_email["has_analysis"] is True
        assert target_email["threat_category"] == "PHISHING"
        assert target_email["static_risk_label"] in ("CRITICAL", "SUSPICIOUS")
        assert target_email["total_actions_count"] >= 1
        assert target_email["pending_approval_count"] >= 1
        assert target_email["primary_action_type"] == "QUARANTINE_EMAIL"
        assert target_email["primary_action_state"] == "PENDING_APPROVAL"

        # 2. Test GET /api/emails/{email_id} detail
        detail_resp = await ac.get(f"/api/emails/{email_id}")
        assert detail_resp.status_code == 200
        detail = detail_resp.json()
        assert detail["id"] == email_id
        assert detail["scenario_id"] == "scenario_phishing"
        assert detail["sanitized_text"] is not None

        # Verify static inspection findings
        static_insp = detail["static_inspection"]
        assert static_insp["static_risk_label"] in ("CRITICAL", "SUSPICIOUS")
        assert static_insp["threat_indicators_count"] > 0
        assert len(static_insp["threat_indicators"]) > 0

        # Verify telemetry
        assert detail["telemetry"] is not None
        assert detail["telemetry"]["provider_mode"] in ("DEMO_FALLBACK", "REAL_CELESTO")
        assert detail["telemetry"]["network_mode"] == "off"

        # Verify advisory LLM analysis
        assert detail["latest_analysis"] is not None
        assert detail["latest_analysis"]["is_advisory_only"] is True
        assert detail["latest_analysis"]["threat_category"] == "PHISHING"

        # Verify action proposals
        assert len(detail["actions"]) >= 1
        first_act = detail["actions"][0]
        assert first_act["action_type"] == "QUARANTINE_EMAIL"
        assert first_act["state"] == "PENDING_APPROVAL"
        assert first_act["is_human_approved"] is False

@pytest.mark.asyncio
async def test_email_endpoints_are_strictly_read_only():
    """Verify that email endpoints do not permit POST/PUT/DELETE or action state changes."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        post_resp = await ac.post("/api/emails", json={"foo": "bar"})
        assert post_resp.status_code == 405  # Method Not Allowed

        delete_resp = await ac.delete("/api/emails/any-id")
        assert delete_resp.status_code == 405  # Method Not Allowed
