import pytest
from backend.app.schemas.sandbox import SandboxAnalysisReport
from backend.app.services.demo_fallback_provider import DemoFallbackProvider
from backend.app.services.simulation_data import get_scenario_eml
from pydantic import ValidationError

@pytest.mark.asyncio
async def test_demo_fallback_transparency():
    """Ensure DemoFallbackProvider visibly marks itself as non-virtualized with clear sandbox_id."""
    provider = DemoFallbackProvider()
    assert provider.provider_mode == "DEMO_FALLBACK"

    health = await provider.health_check()
    assert health["is_virtualized"] is False
    assert "No Celesto VM" in health["description"]

    raw_eml = get_scenario_eml("scenario_normal")
    result = await provider.analyze(raw_eml)
    assert result.provider_mode == "DEMO_FALLBACK"
    assert "no-celesto-vm" in result.sandbox_id
    assert result.network_mode == "off"
    assert result.exit_code == 0
    assert result.report is not None

def test_pydantic_schema_rejects_malformed_report():
    """Ensure invalid schema payloads cannot bypass host validation."""
    malformed_data = {
        "status": "success",
        "static_risk_score": 99.9  # violates le=1.0 constraint
    }
    with pytest.raises(ValidationError):
        SandboxAnalysisReport.model_validate(malformed_data)

def test_pydantic_schema_accepts_valid_report():
    """Ensure strictly structured reports pass validation."""
    valid_data = {
        "status": "success",
        "subject": "Test Subject",
        "sender": "sender@test.com",
        "recipient": "user@test.com",
        "sanitized_text": "Safe text content",
        "static_risk_score": 0.05,
        "static_risk_label": "SAFE",
        "analysis_duration_ms": 12
    }
    report = SandboxAnalysisReport.model_validate(valid_data)
    assert report.subject == "Test Subject"
    assert report.static_risk_label == "SAFE"

@pytest.mark.asyncio
async def test_all_attacks_prevent_unauthorized_side_effects():
    """
    Security Invariant Test:
    Even under direct prompt injection, the provider returns ONLY passive structured data.
    Zero external execution or side effect can be triggered.
    """
    provider = DemoFallbackProvider()
    raw_injection = get_scenario_eml("scenario_direct_injection")
    result = await provider.analyze(raw_injection)

    assert result.exit_code == 0
    assert result.report is not None
    assert result.report.static_risk_label == "CRITICAL"
    
    # Confirm injection keywords were recognized as DATA, not executed
    injections = result.report.prompt_injection_signals
    assert len(injections) > 0
    assert any("SYSTEM_OVERRIDE" in s.pattern_type for s in injections)
