import type {
  CelestoStatusResponse,
  CelestoTelemetryItem,
  ScenarioListResponse,
  SimulationTriggerRequest,
  SimulationTriggerResponse,
  EmailListResponse,
  EmailDetailResponse,
  LLMAnalysisDetailResponse,
  ActionListResponse,
  ActionProposalResponse,
  ActionExecutionResponse,
  ActionState,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://127.0.0.1:8000';

async function handleResponse<T>(res: Response): Promise<T> {
  if (!res.ok) {
    let errorDetail = `HTTP ${res.status}: ${res.statusText}`;
    try {
      const data = await res.json();
      if (data && data.detail) {
        errorDetail = typeof data.detail === 'string' ? data.detail : JSON.stringify(data.detail);
      }
    } catch {
      // Non-JSON response
    }
    throw new Error(errorDetail);
  }
  return res.json();
}

export const api = {
  // Celesto Telemetry & System Status
  async getCelestoStatus(): Promise<CelestoStatusResponse> {
    const res = await fetch(`${API_BASE_URL}/api/celesto/status`);
    return handleResponse<CelestoStatusResponse>(res);
  },

  async getCelestoTelemetry(limit = 50): Promise<CelestoTelemetryItem[]> {
    const res = await fetch(`${API_BASE_URL}/api/celesto/telemetry?limit=${limit}`);
    return handleResponse<CelestoTelemetryItem[]>(res);
  },

  // Attack Simulator
  async getScenarios(): Promise<ScenarioListResponse> {
    const res = await fetch(`${API_BASE_URL}/api/simulator/scenarios`);
    return handleResponse<ScenarioListResponse>(res);
  },

  async triggerScenario(req: SimulationTriggerRequest): Promise<SimulationTriggerResponse> {
    const res = await fetch(`${API_BASE_URL}/api/simulator/trigger`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(req),
    });
    return handleResponse<SimulationTriggerResponse>(res);
  },

  // Email Queue & Deep Inspection
  async getEmails(limit = 100): Promise<EmailListResponse> {
    const res = await fetch(`${API_BASE_URL}/api/emails?limit=${limit}`);
    return handleResponse<EmailListResponse>(res);
  },

  async getEmail(emailId: string): Promise<EmailDetailResponse> {
    const res = await fetch(`${API_BASE_URL}/api/emails/${encodeURIComponent(emailId)}`);
    return handleResponse<EmailDetailResponse>(res);
  },

  // Advisory LLM Analysis
  async getAnalysis(emailId: string): Promise<LLMAnalysisDetailResponse> {
    const res = await fetch(`${API_BASE_URL}/api/analysis/${encodeURIComponent(emailId)}`);
    return handleResponse<LLMAnalysisDetailResponse>(res);
  },

  async triggerAnalysis(emailId: string): Promise<LLMAnalysisDetailResponse> {
    const res = await fetch(`${API_BASE_URL}/api/analysis/${encodeURIComponent(emailId)}`, {
      method: 'POST',
    });
    return handleResponse<LLMAnalysisDetailResponse>(res);
  },

  // Deterministic Policy & Human Approval Actions
  async getActions(emailId?: string, state?: ActionState): Promise<ActionListResponse> {
    const params = new URLSearchParams();
    if (emailId) params.append('email_id', emailId);
    if (state) params.append('state', state);
    const query = params.toString() ? `?${params.toString()}` : '';
    const res = await fetch(`${API_BASE_URL}/api/actions${query}`);
    return handleResponse<ActionListResponse>(res);
  },

  async getAction(actionId: string): Promise<ActionProposalResponse> {
    const res = await fetch(`${API_BASE_URL}/api/actions/${encodeURIComponent(actionId)}`);
    return handleResponse<ActionProposalResponse>(res);
  },

  async proposeActions(emailId: string): Promise<ActionProposalResponse[]> {
    const res = await fetch(`${API_BASE_URL}/api/actions/propose/${encodeURIComponent(emailId)}`, {
      method: 'POST',
    });
    return handleResponse<ActionProposalResponse[]>(res);
  },

  async approveAction(actionId: string, notes?: string): Promise<ActionProposalResponse> {
    const res = await fetch(`${API_BASE_URL}/api/actions/${encodeURIComponent(actionId)}/approve`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ notes }),
    });
    return handleResponse<ActionProposalResponse>(res);
  },

  async rejectAction(actionId: string, reason: string): Promise<ActionProposalResponse> {
    const res = await fetch(`${API_BASE_URL}/api/actions/${encodeURIComponent(actionId)}/reject`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason }),
    });
    return handleResponse<ActionProposalResponse>(res);
  },

  async executeAction(actionId: string): Promise<ActionExecutionResponse> {
    const res = await fetch(`${API_BASE_URL}/api/actions/${encodeURIComponent(actionId)}/execute`, {
      method: 'POST',
    });
    return handleResponse<ActionExecutionResponse>(res);
  },
};
