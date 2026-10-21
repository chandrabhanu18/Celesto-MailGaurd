import os
import json
import pytest
from backend.app.config import settings

@pytest.mark.asyncio
async def test_real_celesto_smoke():
    """
    Real Celesto Integration & Quarantine Smoke Test.
    Strictly conditional on CELESTO_API_KEY availability.
    """
    api_key = os.environ.get("CELESTO_API_KEY") or settings.CELESTO_API_KEY
    if not api_key or not api_key.strip():
        pytest.skip("CELESTO_API_KEY not configured. Skipping live Celesto Cloud smoke test (DEMO_FALLBACK active).")

    try:
        from celesto import Computer
    except ImportError as e:
        pytest.fail(f"celesto package could not be imported: {e}")

    computer = None
    try:
        # 1. Spin up real Celesto Computer with network disabled
        computer = Computer(
            provider="cloud",
            network_policy={"mode": "off"},
            template_id="coding-agent",
        )
        assert computer is not None
        assert getattr(computer, "name", None) is not None

        # 2. Check for Python interpreter in guest
        py3_res = computer.run("python3 --version")
        py3_exit = py3_res["exit_code"] if isinstance(py3_res, dict) else py3_res.exit_code

        if py3_exit == 0:
            py_cmd = "python3"
            version_str = py3_res["stdout"] if isinstance(py3_res, dict) else py3_res.stdout
        else:
            py_res = computer.run("python --version")
            py_exit = py_res["exit_code"] if isinstance(py_res, dict) else py_res.exit_code
            if py_exit == 0:
                py_cmd = "python"
                version_str = py_res["stdout"] if isinstance(py_res, dict) else py_res.stdout
            else:
                pytest.fail("Smoke Test Failure: Guest microVM lacks Python runtime under disabled network policy.")

        print(f"Guest Python verified: {version_str.strip()} using command '{py_cmd}'")

        # 3. Verified Network Lockdown Probe using Python standard library
        # Must fail due to network denial, distinguishing network failure from tool missing
        net_probe_code = (
            "import urllib.request, sys; "
            "try:\n"
            "    urllib.request.urlopen('https://example.com', timeout=3)\n"
            "    sys.exit(0)\n"  # Connection succeeded -> FAILURE under network_policy off!
            "except Exception as e:\n"
            "    print('EXPECTED_NETWORK_DENIAL:', type(e).__name__)\n"
            "    sys.exit(42)\n"  # Expected denial exit code
        )
        net_res = computer.run(f'{py_cmd} -c "{net_probe_code}"')
        net_exit = net_res["exit_code"] if isinstance(net_res, dict) else net_res.exit_code
        net_stdout = net_res["stdout"] if isinstance(net_res, dict) else net_res.stdout

        assert net_exit == 42, (
            f"Network isolation failure! Outbound internet connection succeeded or probe failed unexpectedly. "
            f"Exit: {net_exit}, Output: {net_stdout}"
        )
        assert "EXPECTED_NETWORK_DENIAL" in net_stdout

        # 4. Upload and execute test probe
        test_script_content = (
            "import json\n"
            "print(json.dumps({'status': 'quarantine_verified', 'network': 'disabled'}))\n"
        )
        import tempfile
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".py") as tf:
            tf.write(test_script_content)
            temp_path = tf.name

        try:
            computer.upload_file(temp_path, "/tmp/probe.py")
            exec_res = computer.run(f"{py_cmd} /tmp/probe.py")
            exec_exit = exec_res["exit_code"] if isinstance(exec_res, dict) else exec_res.exit_code
            exec_stdout = exec_res["stdout"] if isinstance(exec_res, dict) else exec_res.stdout

            assert exec_exit == 0
            parsed = json.loads(exec_stdout.strip())
            assert parsed["status"] == "quarantine_verified"
        finally:
            os.unlink(temp_path)

    finally:
        if computer is not None:
            computer.delete()
