import os
import sys
import uuid
import json
import time
import shutil
import tempfile
import asyncio
from typing import Optional
from pathlib import Path
from pydantic import ValidationError

from backend.app.config import settings
from backend.app.schemas.sandbox import SandboxExecutionResult, SandboxAnalysisReport
from backend.app.services.sandbox_provider import CelestoSandboxProvider

class DemoFallbackProvider(CelestoSandboxProvider):
    """
    Demo Fallback Isolation Provider.
    Executes the static inspector in a stripped-down local subprocess.
    Clearly and visibly marked as a fallback: NEVER presented as real virtualization.
    Used for offline, zero-credential testing and development.
    """

    @property
    def provider_mode(self) -> str:
        return "DEMO_FALLBACK"

    async def health_check(self) -> dict:
        return {
            "status": "ready",
            "provider_mode": "DEMO_FALLBACK",
            "is_virtualized": False,
            "description": "Local subprocess runner (No Celesto VM created. Safe for zero-credential offline demos)."
        }

    async def analyze(self, raw_eml_bytes: bytes, filename: str = "untrusted.eml") -> SandboxExecutionResult:
        start_time = time.time()
        sandbox_id = f"demo-subprocess-no-celesto-vm-{uuid.uuid4().hex[:12]}"
        temp_dir = tempfile.mkdtemp(prefix="mailguard_demo_")

        try:
            inspector_src = settings.SANDBOX_AGENT_DIR / "inspector.py"
            if not inspector_src.exists():
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="off",
                    execution_time_ms=0,
                    exit_code=1,
                    error_message=f"Inspector script missing at {inspector_src}"
                )

            # Write inspector and payload into isolated temp directory
            guest_inspector = Path(temp_dir) / "inspector.py"
            shutil.copyfile(inspector_src, guest_inspector)

            guest_eml = Path(temp_dir) / filename
            with open(guest_eml, "wb") as f:
                f.write(raw_eml_bytes)

            # Restrict subprocess environment to prevent host secrets from leaking
            safe_env = {
                "SYSTEMROOT": os.environ.get("SYSTEMROOT", "C:\\Windows"),
                "PATH": os.environ.get("PATH", ""),
                "PYTHONIOENCODING": "utf-8",
                "PYTHONUTF8": "1"
            }

            # Run in subprocess via asyncio
            cmd = [sys.executable, str(guest_inspector), str(guest_eml)]
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=safe_env,
                cwd=temp_dir
            )

            try:
                stdout_bytes, stderr_bytes = await asyncio.wait_for(
                    proc.communicate(),
                    timeout=settings.EXECUTION_TIMEOUT_SECONDS
                )
            except asyncio.TimeoutError:
                proc.kill()
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="off",
                    execution_time_ms=int((time.time() - start_time) * 1000),
                    exit_code=-1,
                    error_message=f"Execution timed out after {settings.EXECUTION_TIMEOUT_SECONDS}s"
                )

            execution_ms = int((time.time() - start_time) * 1000)

            # Enforce max stdout size invariant
            if len(stdout_bytes) > settings.MAX_SANDBOX_OUTPUT_BYTES:
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="off",
                    execution_time_ms=execution_ms,
                    exit_code=1,
                    error_message=f"Output exceeded maximum size limit ({len(stdout_bytes)} > {settings.MAX_SANDBOX_OUTPUT_BYTES} bytes)"
                )

            if proc.returncode != 0:
                err_text = stderr_bytes.decode("utf-8", errors="replace")[:1000]
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="off",
                    execution_time_ms=execution_ms,
                    exit_code=proc.returncode,
                    error_message=f"Inspector exited with code {proc.returncode}: {err_text}"
                )

            stdout_str = stdout_bytes.decode("utf-8", errors="replace")
            try:
                parsed_json = json.loads(stdout_str)
                validated_report = SandboxAnalysisReport.model_validate(parsed_json)
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="off",
                    execution_time_ms=execution_ms,
                    exit_code=0,
                    report=validated_report
                )
            except json.JSONDecodeError as jde:
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="off",
                    execution_time_ms=execution_ms,
                    exit_code=2,
                    error_message=f"Malformed JSON from inspector: {jde}"
                )
            except ValidationError as ve:
                return SandboxExecutionResult(
                    provider_mode=self.provider_mode,
                    sandbox_id=sandbox_id,
                    network_mode="off",
                    execution_time_ms=execution_ms,
                    exit_code=3,
                    error_message=f"Inspector JSON failed schema validation: {ve}"
                )

        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
