from abc import ABC, abstractmethod
from backend.app.schemas.sandbox import SandboxExecutionResult

class CelestoSandboxProvider(ABC):
    """
    Abstract interface for executing untrusted email payloads inside an isolated quarantine.
    Application components depend strictly on this interface, never directly on Celesto SDK calls.
    """

    @property
    @abstractmethod
    def provider_mode(self) -> str:
        """Returns 'REAL_CELESTO' or 'DEMO_FALLBACK'."""
        pass

    @abstractmethod
    async def analyze(self, raw_eml_bytes: bytes, filename: str = "untrusted.eml") -> SandboxExecutionResult:
        """
        Executes static analysis in an isolated sandbox and returns a validated SandboxExecutionResult.
        Guarantees that raw stdout/stderr is size-capped and validated before returning.
        """
        pass

    @abstractmethod
    async def health_check(self) -> dict:
        """Returns status, availability, and active provider info."""
        pass
