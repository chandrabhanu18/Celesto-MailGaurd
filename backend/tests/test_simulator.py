import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.db.database import init_db

@pytest.fixture(autouse=True)
async def setup_db():
    await init_db()

@pytest.mark.asyncio
async def test_list_all_9_scenarios():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.get("/api/simulator/scenarios")
        assert resp.status_code == 200
        data = resp.json()
        assert "scenarios" in data
        assert len(data["scenarios"]) == 9

@pytest.mark.asyncio
async def test_trigger_all_9_scenarios_pipeline():
    """Ensure every single one of the 9 fixtures executes end-to-end through the quarantine pipeline."""
    from backend.app.services.simulation_data import FIXTURE_METADATA
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        for meta in FIXTURE_METADATA:
            resp = await ac.post("/api/simulator/trigger", json={"scenario_id": meta.scenario_id})
            assert resp.status_code == 200, f"Scenario {meta.scenario_id} failed with status {resp.status_code}"
            body = resp.json()
            assert body["scenario_id"] == meta.scenario_id
            assert body["unauthorized_side_effects_prevented"] is True
            assert body["execution"]["exit_code"] == 0
            assert body["execution"]["report"] is not None

@pytest.mark.asyncio
async def test_trigger_phishing_scenario():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/api/simulator/trigger", json={"scenario_id": "scenario_phishing"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["scenario_id"] == "scenario_phishing"
        assert body["unauthorized_side_effects_prevented"] is True
        assert body["execution"]["report"]["static_risk_label"] in ("CRITICAL", "SUSPICIOUS")
        assert "QUARANTINED" in body["security_verdict"]

@pytest.mark.asyncio
async def test_trigger_prompt_injection_scenario():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        resp = await ac.post("/api/simulator/trigger", json={"scenario_id": "scenario_direct_injection"})
        assert resp.status_code == 200
        body = resp.json()
        assert body["scenario_id"] == "scenario_direct_injection"
        assert body["unauthorized_side_effects_prevented"] is True
        assert body["execution"]["report"]["static_risk_label"] == "CRITICAL"
        assert len(body["execution"]["report"]["prompt_injection_signals"]) >= 1

@pytest.mark.asyncio
async def test_celesto_telemetry_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Trigger an execution first
        await ac.post("/api/simulator/trigger", json={"scenario_id": "scenario_interview"})
        
        # Verify telemetry list
        resp = await ac.get("/api/celesto/telemetry")
        assert resp.status_code == 200
        telemetry_data = resp.json()
        assert isinstance(telemetry_data, list)
        assert len(telemetry_data) >= 1
        assert "provider_mode" in telemetry_data[0]
        assert "sandbox_id" in telemetry_data[0]
        assert telemetry_data[0]["network_mode"] == "off"
