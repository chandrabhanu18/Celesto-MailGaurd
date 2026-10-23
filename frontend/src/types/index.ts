// TypeScript schema definitions mirroring MailGuard backend models

export type ThreatCategory =
  | 'BENIGN'
  | 'PHISHING'
  | 'PROMPT_INJECTION'
  | 'MALWARE'
  | 'SCAM'
  | 'SUSPICIOUS'
  | 'OTHER';

export type ThreatLevel = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';

export type ActionType =
  | 'QUARANTINE_EMAIL'
  | 'FLAG_EMAIL'
  | 'CREATE_CALENDAR_EVENT'
  | 'GENERATE_REPLY'
  | 'PUBLISH_SOCIAL_CONTENT';

export type ActionState =
  | 'PENDING_APPROVAL'
  | 'APPROVED'
  | 'REJECTED'
  | 'EXECUTED'
  | 'FAILED';

export interface ExtractedURL {
  url: string;
  domain: string;
  is_ip_address: boolean;
  is_suspicious_homoglyph: boolean;
  is_known_suspicious_tld: boolean;
  risk_notes?: string | null;
}

export interface AttachmentMeta {
  filename: string;
  content_type: string;
  size_bytes: number;
  sha256_hash: string;
  entropy: number;
  is_executable_or_script: boolean;
  is_archive: boolean;
  archive_traversal_risk: boolean;
  suspicious_notes?: string | null;
}

export interface ThreatIndicator {
  indicator_type: string;
  severity: string;
  description: string;
  matched_pattern?: string | null;
}

export interface PromptInjectionSignal {
  pattern_type: string;
  confidence: number;
  matched_snippet: string;
  description: string;
}

export interface SandboxAnalysisReport {
  status: string;
  subject: string;
  sender: string;
  recipient: string;
  date_str: string;
  has_html: boolean;
  sanitized_text: string;
  extracted_urls: ExtractedURL[];
  attachments: AttachmentMeta[];
  threat_indicators: ThreatIndicator[];
  prompt_injection_signals: PromptInjectionSignal[];
  static_risk_score: number;
  static_risk_label: string;
  analysis_duration_ms: number;
}

export interface SandboxExecutionResult {
  provider_mode: string;
  sandbox_id: string;
  network_mode: string;
  execution_time_ms: number;
  exit_code: number;
  report?: SandboxAnalysisReport | null;
  error_message?: string | null;
  is_quarantine_breach_detected: boolean;
}

export interface ExtractedCalendarEvent {
  title: string;
  date: string;
  start_time?: string | null;
  end_time?: string | null;
  timezone?: string | null;
  location?: string | null;
  description?: string | null;
}

export interface LLMAnalysisDetailResponse {
  id: string;
  email_id: string;
  provider: string;
  model: string;
  threat_category: ThreatCategory;
  threat_level: ThreatLevel;
  confidence: number;
  urgency: number;
  explanation: string;
  indicators: string[];
  recommended_action: string;
  calendar_event_detected: boolean;
  extracted_calendar_event?: ExtractedCalendarEvent | null;
  is_advisory_only: boolean;
  created_at: string;
}

export interface ActionProposalResponse {
  id: string;
  email_id: string;
  source_analysis_id?: string | null;
  action_type: ActionType;
  state: ActionState;
  reason: string;
  policy_rule: string;
  risk_level: string;
  payload: Record<string, any>;
  rejection_reason?: string | null;
  execution_result?: Record<string, any> | null;
  is_human_approved: boolean;
  created_at: string;
  approved_at?: string | null;
  rejected_at?: string | null;
  executed_at?: string | null;
}

export interface ActionExecutionResponse {
  action_id: string;
  action_type: ActionType;
  state: ActionState;
  executed_at: string;
  is_simulated: boolean;
  execution_result: Record<string, any>;
}

export interface ActionListResponse {
  actions: ActionProposalResponse[];
  total: number;
}

export interface SimulationScenarioMeta {
  scenario_id: string;
  title: string;
  category: string;
  description: string;
  expected_risk: string;
  attack_type?: string | null;
}

export interface ScenarioListResponse {
  scenarios: SimulationScenarioMeta[];
}

export interface SimulationTriggerRequest {
  scenario_id: string;
  run_llm_analysis?: boolean;
  propose_actions?: boolean;
}

export interface SimulationTriggerResponse {
  scenario_id: string;
  title: string;
  category: string;
  email_id: string;
  execution: SandboxExecutionResult;
  security_verdict: string;
  unauthorized_side_effects_prevented: boolean;
  invariants_maintained: string[];
  llm_analysis?: LLMAnalysisDetailResponse | null;
  llm_provider_used?: string | null;
  proposed_actions: ActionProposalResponse[];
  has_pending_actions: boolean;
}

export interface EmailListItem {
  id: string;
  scenario_id?: string | null;
  source: string;
  sender: string;
  recipient: string;
  subject: string;
  date_str: string;
  created_at: string;
  static_risk_label: string;
  static_risk_score: number;
  threat_indicators_count: number;
  has_analysis: boolean;
  threat_category?: ThreatCategory | null;
  threat_level?: ThreatLevel | null;
  urgency?: number | null;
  confidence?: number | null;
  recommended_action?: string | null;
  calendar_event_detected: boolean;
  total_actions_count: number;
  pending_approval_count: number;
  primary_action_type?: ActionType | null;
  primary_action_state?: ActionState | null;
  is_quarantined: boolean;
}

export interface EmailListResponse {
  emails: EmailListItem[];
  total: number;
}

export interface StaticInspectionDetail {
  static_risk_label: string;
  static_risk_score: number;
  threat_indicators_count: number;
  threat_indicators: ThreatIndicator[] | Record<string, any>[];
  extracted_urls: string[];
  has_html: boolean;
  has_prompt_injection: boolean;
  has_suspicious_homoglyph: boolean;
  has_ip_url: boolean;
  has_zero_width_chars: boolean;
  analysis_duration_ms: number;
}

export interface TelemetrySummary {
  id: string;
  provider_mode: string;
  sandbox_id: string;
  network_mode: string;
  execution_time_ms: number;
  exit_code: number;
  indicators: Record<string, any>[];
  error_message?: string | null;
  created_at?: string | null;
}

export interface EmailDetailResponse {
  id: string;
  scenario_id?: string | null;
  source: string;
  sender: string;
  recipient: string;
  subject: string;
  date_str: string;
  sanitized_text: string;
  created_at: string;
  static_inspection: StaticInspectionDetail;
  telemetry?: TelemetrySummary | null;
  latest_analysis?: LLMAnalysisDetailResponse | null;
  actions: ActionProposalResponse[];
}

export interface CelestoStatusResponse {
  status: string;
  provider_mode: string;
  is_virtualized: boolean;
  description: string;
  configured?: boolean;
  celesto_provider?: string;
  template_id?: string;
  network_policy?: Record<string, any>;
}

export interface CelestoTelemetryItem {
  id: string;
  email_id: string;
  email_subject: string;
  static_risk_label: string;
  provider_mode: string;
  sandbox_id: string;
  network_mode: string;
  execution_time_ms: number;
  exit_code: number;
  indicators: Record<string, any>[];
  error_message?: string | null;
  created_at?: string | null;
}
