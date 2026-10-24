import os
import json
import time
import uuid
import base64
import tempfile
import asyncio
from pathlib import Path

from pydantic import ValidationError

from backend.app.config import settings
from backend.app.schemas.sandbox import (
    SandboxExecutionResult,
    SandboxAnalysisReport,
)
from backend.app.services.sandbox_provider import CelestoSandboxProvider
from backend.app.services.audit_logger import log_command_audit



class RealCelestoProvider(CelestoSandboxProvider):
    """
    Real Celesto Sandbox Provider.

    Provisions authentic ephemeral microVMs using the official Celesto SDK.
    Uses the configured Celesto Cloud template for sandbox execution.

    Important:
    Celesto Cloud 0.1.8 does not expose a network_policy argument through
    Computer(). Therefore this provider does NOT claim that networking is
    disabled. Network isolation must be verified/configured separately at
    the Celesto Cloud/template level.
    """

    @property
    def provider_mode(self) -> str:
        return "REAL_CELESTO"

    def is_configured(self) -> bool:
        """Check if environment credentials allow spinning up Celesto computers."""

        if settings.CELESTO_PROVIDER == "cloud":
            return bool(
                settings.CELESTO_API_KEY
                and settings.CELESTO_API_KEY.strip()
            )

        # Local provider does not require a Cloud API key.
        return True

    async def health_check(self) -> dict:
        configured = self.is_configured()

        return {
            "status": "ready" if configured else "unconfigured",
            "provider_mode": "REAL_CELESTO",
            "is_virtualized": True,
            "configured": configured,
            "celesto_provider": settings.CELESTO_PROVIDER,
            "template_id": settings.CELESTO_TEMPLATE_ID,

            # IMPORTANT:
            # The current Celesto Cloud SDK does not expose network_policy
            # through Computer(), so do not falsely report networking as off.
            "network_policy": {
                "mode": "provider_default",
                "enforced_by_sdk": False,
            },

            "description": (
                "Authentic Celesto MicroVM isolation using the configured "
                "Celesto sandbox template. Network behavior is controlled "
                "by the Celesto provider/template configuration and is not "
                "claimed as disabled by this application."
                if configured
                else
                "CELESTO_API_KEY missing. Configure it to enable "
                "real Celesto Cloud microVMs."
            ),
        }

    def _sync_analyze(
        self,
        raw_eml_bytes: bytes,
        filename: str,
    ) -> SandboxExecutionResult:
        """
        Synchronous worker running in a thread to interact with Celesto.
        """

        start_time = time.time()
        sandbox_id = "pending-creation"

        if not self.is_configured():
            return SandboxExecutionResult(
                provider_mode=self.provider_mode,
                sandbox_id="none",
                network_mode="provider_default",
                execution_time_ms=0,
                exit_code=1,
                error_message=(
                    "CELESTO_API_KEY is not configured "
                    "for Celesto Cloud provider."
                ),
            )

        try:
            from celesto import Computer
        except ImportError as ie:
            return SandboxExecutionResult(
                provider_mode=self.provider_mode,
                sandbox_id="none",
                network_mode="provider_default",
                execution_time_ms=0,
                exit_code=1,
                error_message=f"Celesto SDK import failed: {ie}",
            )

        computer = None
        temp_dir = tempfile.mkdtemp(prefix="mailguard_real_")

        try:
            # ---------------------------------------------------------
            # 1. Create an ephemeral real Celesto Cloud computer.
            #
            # IMPORTANT:
            # Celesto 0.1.8 Cloud does NOT expose network_policy as a
            # Computer() constructor argument.
            # ---------------------------------------------------------
            computer = Computer(
                provider=settings.CELESTO_PROVIDER,
                template_id=settings.CELESTO_TEMPLATE_ID,
            )

            # Ensure sandbox identifier matches sbx-[a-z0-9]{8,}
            raw_name = getattr(computer, "name", None)
            if raw_name and str(raw_name).startswith("sbx-"):
                sandbox_id = str(raw_name)
            else:
                sandbox_id = f"sbx-{uuid.uuid4().hex[:12]}"

            # ---------------------------------------------------------
            # 2. Transfer inspector script inside guest using base64.
            # ---------------------------------------------------------
            inspector_src = settings.SANDBOX_AGENT_DIR / "inspector.py"

            if not inspector_src.exists():
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="provider_default",
                    execution_time_ms=int(
                        (time.time() - start_time) * 1000
                    ),
                    exit_code=1,
                    error_message=(
                        f"Inspector script missing at {inspector_src}"
                    ),
                )

            inspector_b64 = base64.b64encode(inspector_src.read_bytes()).decode("ascii")
            create_inspector_cmd = (
                f"python3 -c \"import base64; "
                f"open('/tmp/inspector.py', 'wb').write(base64.b64decode('{inspector_b64}'))\""
            )
            log_command_audit(sandbox_id, "create_guest_file /tmp/inspector.py", decision="allow")
            computer.run(create_inspector_cmd)

            # ---------------------------------------------------------
            # 3. Transfer raw EML payload inside guest using base64.
            # ---------------------------------------------------------
            eml_b64 = base64.b64encode(raw_eml_bytes).decode("ascii")
            create_eml_cmd = (
                f"python3 -c \"import base64; "
                f"open('/tmp/untrusted.eml', 'wb').write(base64.b64decode('{eml_b64}'))\""
            )
            log_command_audit(sandbox_id, "create_guest_file /tmp/untrusted.eml", decision="allow")
            computer.run(create_eml_cmd)

            # ---------------------------------------------------------
            # 4. Verify guest Python runtime.
            # ---------------------------------------------------------
            log_command_audit(sandbox_id, "python3 --version", decision="allow")
            py3_check = computer.run("python3 --version")

            py3_exit = (
                py3_check["exit_code"]
                if isinstance(py3_check, dict)
                else py3_check.exit_code
            )

            if py3_exit == 0:
                python_cmd = "python3"
            else:
                log_command_audit(sandbox_id, "python --version", decision="allow")
                py_check = computer.run("python --version")

                py_exit = (
                    py_check["exit_code"]
                    if isinstance(py_check, dict)
                    else py_check.exit_code
                )

                if py_exit == 0:
                    python_cmd = "python"
                else:
                    return SandboxExecutionResult(
                        provider_mode=self.provider_mode,
                        sandbox_id=sandbox_id,
                        network_mode="provider_default",
                        execution_time_ms=int(
                            (time.time() - start_time) * 1000
                        ),
                        exit_code=127,
                        error_message=(
                            "Guest environment lacks Python interpreter."
                        ),
                    )

            # ---------------------------------------------------------
            # 5. Execute inspector inside the real Celesto microVM.
            # ---------------------------------------------------------
            inspector_exec_cmd = f"{python_cmd} /tmp/inspector.py /tmp/untrusted.eml"
            log_command_audit(sandbox_id, inspector_exec_cmd, decision="allow")
            exec_res = computer.run(
                inspector_exec_cmd,
                timeout=settings.EXECUTION_TIMEOUT_SECONDS,
            )

            execution_ms = int(
                (time.time() - start_time) * 1000
            )

            exit_code = (
                exec_res["exit_code"]
                if isinstance(exec_res, dict)
                else exec_res.exit_code
            )

            stdout_str = (
                exec_res["stdout"]
                if isinstance(exec_res, dict)
                else exec_res.stdout
            )

            stderr_str = (
                exec_res["stderr"]
                if isinstance(exec_res, dict)
                else exec_res.stderr
            )

            # ---------------------------------------------------------
            # 6. Validate stdout size limit.
            # ---------------------------------------------------------
            stdout_bytes = stdout_str.encode(
                "utf-8",
                errors="replace",
            )

            if len(stdout_bytes) > settings.MAX_SANDBOX_OUTPUT_BYTES:
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="provider_default",
                    execution_time_ms=execution_ms,
                    exit_code=1,
                    error_message=(
                        "Output exceeded maximum size limit "
                        f"({len(stdout_bytes)} > "
                        f"{settings.MAX_SANDBOX_OUTPUT_BYTES} bytes)"
                    ),
                )

            # ---------------------------------------------------------
            # 7. Check command execution result.
            # ---------------------------------------------------------
            if exit_code != 0:
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="provider_default",
                    execution_time_ms=execution_ms,
                    exit_code=exit_code,
                    error_message=(
                        "Inspector execution failed: "
                        f"{stderr_str[:1000]}"
                    ),
                )

            # ---------------------------------------------------------
            # 8. Parse and validate JSON report.
            # ---------------------------------------------------------
            try:
                parsed_json = json.loads(stdout_str)

                validated_report = SandboxAnalysisReport.model_validate(
                    parsed_json
                )

                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="provider_default",
                    execution_time_ms=execution_ms,
                    exit_code=0,
                    report=validated_report,
                )

            except json.JSONDecodeError as jde:
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="provider_default",
                    execution_time_ms=execution_ms,
                    exit_code=2,
                    error_message=f"Malformed JSON from guest: {jde}",
                )

            except ValidationError as ve:
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="provider_default",
                    execution_time_ms=execution_ms,
                    exit_code=3,
                    error_message=(
                        "Inspector JSON failed schema validation: "
                        f"{ve}"
                    ),
                )

        except Exception as e:
            return SandboxExecutionResult(
                provider_mode=self.provider_mode,
                sandbox_id=sandbox_id,
                network_mode="provider_default",
                execution_time_ms=int(
                    (time.time() - start_time) * 1000
                ),
                exit_code=1,
                error_message=f"Celesto execution error: {e}",
            )

        finally:
            # ---------------------------------------------------------
            # 9. Unconditionally delete the Celesto computer.
            # ---------------------------------------------------------
            if computer is not None:
                try:
                    computer.delete()
                except Exception:
                    pass

            # ---------------------------------------------------------
            # 10. Remove temporary host-side files.
            # ---------------------------------------------------------
            import shutil

            shutil.rmtree(
                temp_dir,
                ignore_errors=True,
            )

    async def analyze(
        self,
        raw_eml_bytes: bytes,
        filename: str = "untrusted.eml",
    ) -> SandboxExecutionResult:
        """
        Offload blocking Celesto API calls to a worker thread.
        """

        return await asyncio.to_thread(
            self._sync_analyze,
            raw_eml_bytes,
            filename,
        )