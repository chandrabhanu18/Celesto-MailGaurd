import os
import json
import pytest

from backend.app.config import settings


@pytest.mark.asyncio
async def test_real_celesto_smoke():
    """
    Real Celesto Integration Smoke Test.

    Strictly conditional on CELESTO_API_KEY availability.

    Verifies that a real Celesto Cloud microVM can:
    - be created successfully
    - execute commands
    - execute Python code inside the guest
    - create and execute a file inside the guest
    - be cleaned up successfully

    Network isolation is intentionally NOT claimed here because
    Celesto Cloud 0.1.8 does not expose network_policy through
    the Computer() constructor.
    """

    api_key = (
        os.environ.get("CELESTO_API_KEY")
        or settings.CELESTO_API_KEY
    )

    if not api_key or not api_key.strip():
        pytest.skip(
            "CELESTO_API_KEY not configured. "
            "Skipping live Celesto Cloud smoke test."
        )

    try:
        from celesto import Computer
    except ImportError as e:
        pytest.fail(
            f"celesto package could not be imported: {e}"
        )

    computer = None

    try:
        # 1. Spin up a real Celesto Cloud Computer.
        computer = Computer(
            provider="cloud",
            template_id="coding-agent",
        )

        assert computer is not None

        # 2. Check for Python interpreter in guest.
        py3_res = computer.run("python3 --version")

        py3_exit = (
            py3_res["exit_code"]
            if isinstance(py3_res, dict)
            else py3_res.exit_code
        )

        if py3_exit == 0:
            py_cmd = "python3"
            version_str = (
                py3_res["stdout"]
                if isinstance(py3_res, dict)
                else py3_res.stdout
            )
        else:
            py_res = computer.run("python --version")

            py_exit = (
                py_res["exit_code"]
                if isinstance(py_res, dict)
                else py_res.exit_code
            )

            if py_exit == 0:
                py_cmd = "python"
                version_str = (
                    py_res["stdout"]
                    if isinstance(py_res, dict)
                    else py_res.stdout
                )
            else:
                pytest.fail(
                    "Smoke Test Failure: "
                    "Guest microVM lacks a Python runtime."
                )

        print(
            f"Guest Python verified: "
            f"{version_str.strip()} "
            f"using command '{py_cmd}'"
        )

        # 3. Execute a simple command inside the real microVM.
        command_res = computer.run(
            "echo MAILGUARD_CELESTO_EXECUTION_VERIFIED"
        )

        command_exit = (
            command_res["exit_code"]
            if isinstance(command_res, dict)
            else command_res.exit_code
        )

        command_stdout = (
            command_res["stdout"]
            if isinstance(command_res, dict)
            else command_res.stdout
        )

        assert command_exit == 0
        assert (
            "MAILGUARD_CELESTO_EXECUTION_VERIFIED"
            in command_stdout
        )

        # 4. Create a Python probe directly inside the guest.
        #
        # The Celesto 0.1.8 Computer wrapper does not expose
        # upload_file(), so we create the file using a shell command
        # executed INSIDE the Celesto microVM.
        probe_code = (
            "import json; "
            "print(json.dumps({"
            "'status': 'celesto_execution_verified', "
            "'execution_target': 'celesto_cloud_microvm'"
            "}))"
        )

        create_probe_command = (
            f"printf '%s\\n' "
            f"\"{probe_code}\" "
            f"> /tmp/mailguard_probe.py"
        )

        create_res = computer.run(create_probe_command)

        create_exit = (
            create_res["exit_code"]
            if isinstance(create_res, dict)
            else create_res.exit_code
        )

        assert create_exit == 0

        # 5. Execute the probe inside the guest.
        exec_res = computer.run(
            f"{py_cmd} /tmp/mailguard_probe.py"
        )

        exec_exit = (
            exec_res["exit_code"]
            if isinstance(exec_res, dict)
            else exec_res.exit_code
        )

        exec_stdout = (
            exec_res["stdout"]
            if isinstance(exec_res, dict)
            else exec_res.stdout
        )

        assert exec_exit == 0

        parsed = json.loads(exec_stdout.strip())

        assert (
            parsed["status"]
            == "celesto_execution_verified"
        )

        assert (
            parsed["execution_target"]
            == "celesto_cloud_microvm"
        )

        print(
            "Real Celesto Cloud execution verified successfully."
        )

    finally:
        # 6. Always clean up the real Celesto computer.
        if computer is not None:
            computer.delete()
