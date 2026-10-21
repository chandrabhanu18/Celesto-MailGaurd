from backend.app.config import settings
from backend.app.services.sandbox_provider import CelestoSandboxProvider
from backend.app.services.real_celesto_provider import RealCelestoProvider
from backend.app.services.demo_fallback_provider import DemoFallbackProvider

def get_sandbox_provider() -> CelestoSandboxProvider:
    """
    Factory function returning the active sandbox provider based on environment configuration.
    Never misrepresents a fallback as a genuine virtualized microVM.
    """
    mode = settings.SANDBOX_PROVIDER_MODE.lower()
    
    if mode == "real":
        return RealCelestoProvider()
    elif mode == "demo":
        return DemoFallbackProvider()
    else:  # "auto"
        real_p = RealCelestoProvider()
        if real_p.is_configured():
            return real_p
        return DemoFallbackProvider()
