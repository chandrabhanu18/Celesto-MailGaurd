"""
Deterministic Policy Engine for MailGuard.
Consumes Phase 2A static inspection findings and Phase 2B advisory LLM assessments.
Enforces deterministic business rules to generate Action Proposals.
CRITICAL INVARIANTS:
1. LLM recommendations are advisory only; they cannot authorize actions.
2. The Policy Engine creates proposals exclusively in PENDING_APPROVAL state.
3. Every proposal requires explicit human authorization before execution.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from backend.app.schemas.action import ActionType, ActionState
from backend.app.schemas.llm import ThreatCategory, ThreatLevel, LLMAnalysisResult
from backend.app.schemas.sandbox import SandboxAnalysisReport

@dataclass
class ProposedActionDraft:
    action_type: ActionType
    reason: str
    policy_rule: str
    risk_level: str
    payload: Dict[str, Any] = field(default_factory=dict)

class PolicyEngine:
    """
    Deterministic rule-based policy evaluator.
    Independent of LLM prompt manipulation.
    """

    @staticmethod
    def evaluate(
        static_risk_label: str,
        static_risk_score: float,
        threat_category: Optional[str] = None,
        threat_level: Optional[str] = None,
        urgency: int = 1,
        calendar_event_detected: bool = False,
        calendar_event_data: Optional[Dict[str, Any]] = None,
        static_threat_indicators: Optional[List[str]] = None
    ) -> List[ProposedActionDraft]:
        proposals: List[ProposedActionDraft] = []
        static_threat_indicators = static_threat_indicators or []
        cat_upper = (threat_category or "").upper()
        label_upper = (static_risk_label or "").upper()

        # RULE 2: Prompt Injection Quarantine (Highest Priority)
        # Checked via deterministic category or static heuristic indicators
        is_prompt_injection = (
            cat_upper == ThreatCategory.PROMPT_INJECTION.value
            or any("PROMPT_INJECTION" in ind.upper() or "SYSTEM_OVERRIDE" in ind.upper() for ind in static_threat_indicators)
        )
        if is_prompt_injection:
            proposals.append(ProposedActionDraft(
                action_type=ActionType.QUARANTINE_EMAIL,
                reason="Adversarial prompt injection attempt detected. Quarantining email to prevent instruction execution.",
                policy_rule="PROMPT_INJECTION_QUARANTINE",
                risk_level="CRITICAL",
                payload={"static_risk_score": static_risk_score, "threat_category": "PROMPT_INJECTION"}
            ))
            return proposals  # Critical containment terminates further proposals

        # RULE 1: Phishing or Malware Quarantine
        is_phishing_or_malware = (
            cat_upper in (ThreatCategory.PHISHING.value, ThreatCategory.MALWARE.value, ThreatCategory.SCAM.value)
            or (label_upper in ("CRITICAL", "SUSPICIOUS") and static_risk_score >= 0.5)
            or any("HOMOGLYPH" in ind.upper() or "PHISHING" in ind.upper() or "ZIP_SLIP" in ind.upper() for ind in static_threat_indicators)
        )
        if is_phishing_or_malware:
            proposals.append(ProposedActionDraft(
                action_type=ActionType.QUARANTINE_EMAIL,
                reason="High-risk phishing, homoglyph, or malware signals detected. Quarantining email from inbox.",
                policy_rule="PHISHING_OR_MALWARE_QUARANTINE",
                risk_level="HIGH",
                payload={"static_risk_score": static_risk_score, "threat_category": cat_upper or "SUSPICIOUS"}
            ))
            return proposals

        # RULE 3: Calendar Event Creation Proposal (Legitimate only)
        # NEVER executed automatically; requires explicit human confirmation of event details
        if calendar_event_detected and cat_upper == ThreatCategory.BENIGN.value:
            proposals.append(ProposedActionDraft(
                action_type=ActionType.CREATE_CALENDAR_EVENT,
                reason="Meeting or interview schedule detected in verified benign correspondence. Gating event creation for user approval.",
                policy_rule="CALENDAR_EVENT_PROPOSAL",
                risk_level="LOW",
                payload={"event_data": calendar_event_data or {}}
            ))

        # RULE 4: Urgent Legitimate Email Flagging
        if urgency == 5 and cat_upper == ThreatCategory.BENIGN.value:
            proposals.append(ProposedActionDraft(
                action_type=ActionType.FLAG_EMAIL,
                reason="High-urgency legitimate email requiring user awareness. Proposing high-priority mailbox flag.",
                policy_rule="HIGH_URGENCY_FLAG",
                risk_level="MEDIUM",
                payload={"urgency": 5}
            ))

        # RULE 5: Benign Low-Urgency Routine Email (No intrusive actions proposed)
        # Clean emails with no events do not produce disruptive actions.
        return proposals
