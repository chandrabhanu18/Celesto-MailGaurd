import { useState, useEffect, useCallback } from 'react';
import {
  AlertCircle,
  CheckCircle2,
  Info,
  X,
  RefreshCw,
  ServerOff,
} from 'lucide-react';
import type {
  CelestoStatusResponse,
  SimulationScenarioMeta,
  EmailListItem,
  EmailDetailResponse,
  SimulationTriggerResponse,
} from './types';
import { api } from './services/api';
import { Header } from './components/Header';
import { KpiMetrics } from './components/KpiMetrics';
import { ScenarioLauncher } from './components/ScenarioLauncher';
import { EmailQueue } from './components/EmailQueue';
import { InvestigationPanel } from './components/InvestigationPanel';
import { TelemetryDrawer } from './components/TelemetryDrawer';

interface ToastMessage {
  message: string;
  type: 'success' | 'error' | 'info';
}

export function App() {
  // App state
  const [celestoStatus, setCelestoStatus] = useState<CelestoStatusResponse | null>(null);
  const [backendOnline, setBackendOnline] = useState<boolean>(true);
  const [scenarios, setScenarios] = useState<SimulationScenarioMeta[]>([]);
  const [emails, setEmails] = useState<EmailListItem[]>([]);
  const [selectedEmailId, setSelectedEmailId] = useState<string | null>(null);
  const [selectedEmailDetail, setSelectedEmailDetail] = useState<EmailDetailResponse | null>(null);

  // UI state
  const [isLoadingEmails, setIsLoadingEmails] = useState<boolean>(false);
  const [isLoadingDetail, setIsLoadingDetail] = useState<boolean>(false);
  const [isRefreshing, setIsRefreshing] = useState<boolean>(false);
  const [isTriggering, setIsTriggering] = useState<boolean>(false);
  const [isProcessingAction, setIsProcessingAction] = useState<boolean>(false);
  const [isTelemetryOpen, setIsTelemetryOpen] = useState<boolean>(false);
  const [toast, setToast] = useState<ToastMessage | null>(null);

  const showToast = (message: string, type: 'success' | 'error' | 'info' = 'info') => {
    setToast({ message, type });
    setTimeout(() => {
      setToast((prev) => (prev?.message === message ? null : prev));
    }, 4500);
  };

  // Fetch full email detail by explicit ID
  const loadEmailDetail = useCallback(async (emailId: string) => {
    setIsLoadingDetail(true);
    try {
      const detail = await api.getEmail(emailId);
      // Enforce identity correspondence
      if (detail.id !== emailId) {
        throw new Error(`Email ID mismatch: requested ${emailId}, received ${detail.id}`);
      }
      setSelectedEmailDetail(detail);
      setSelectedEmailId(emailId);
    } catch (err: any) {
      showToast(err.message || 'Failed to fetch email investigation detail.', 'error');
    } finally {
      setIsLoadingDetail(false);
    }
  }, []);

  // Load all dashboard data on initial mount or refresh
  const loadDashboardData = useCallback(async () => {
    setIsRefreshing(true);
    try {
      const [statusRes, scenariosRes, emailsRes] = await Promise.all([
        api.getCelestoStatus(),
        api.getScenarios(),
        api.getEmails(),
      ]);

      setCelestoStatus(statusRes);
      setScenarios(scenariosRes.scenarios || []);
      setEmails(emailsRes.emails || []);
      setBackendOnline(true);

      // Invariant: DO NOT automatically select the first email in the queue.
      // Active email is set strictly by explicit scenario trigger or explicit queue click.
    } catch (err: any) {
      setBackendOnline(false);
      showToast('Backend unavailable — start the FastAPI server.', 'error');
    } finally {
      setIsRefreshing(false);
      setIsLoadingEmails(false);
    }
  }, []);

  useEffect(() => {
    setIsLoadingEmails(true);
    loadDashboardData();
  }, [loadDashboardData]);

  // Handle Scenario Execution Trigger:
  // Invariant: selectedScenario.id -> trigger response -> processed email_id -> selectedEmail.id -> analysis.email_id -> action.email_id
  const handleTriggerScenario = async (
    scenarioId: string,
    runLlm: boolean,
    proposeActions: boolean
  ): Promise<SimulationTriggerResponse | null> => {
    setIsTriggering(true);
    // Explicitly clear old investigation detail so no stale email is displayed during execution
    setSelectedEmailDetail(null);
    setSelectedEmailId(null);
    setIsLoadingDetail(true);

    try {
      const result = await api.triggerScenario({
        scenario_id: scenarioId,
        run_llm_analysis: runLlm,
        propose_actions: proposeActions,
      });

      if (!result || !result.email_id) {
        throw new Error('Simulation response missing canonical email_id.');
      }

      const canonicalEmailId = result.email_id;

      // Immediately fetch canonical email investigation detail directly by ID
      const detail = await api.getEmail(canonicalEmailId);

      // Verify Identity Invariant:
      if (detail.id !== canonicalEmailId) {
        throw new Error(`Identity Invariant Failure: Expected email ID ${canonicalEmailId}, received ${detail.id}`);
      }

      // Synchronously set the active investigation email
      setSelectedEmailId(canonicalEmailId);
      setSelectedEmailDetail(detail);

      showToast(`Quarantined & inspected: "${result.title}"`, 'success');

      // Refresh email queue to reflect the newly processed email
      const emailsRes = await api.getEmails();
      setEmails(emailsRes.emails || []);

      return result;
    } catch (err: any) {
      showToast(err.message || 'Quarantine execution failed.', 'error');
      return null;
    } finally {
      setIsTriggering(false);
      setIsLoadingDetail(false);
    }
  };

  // Explicit Email Selection from Queue
  const handleSelectEmail = (emailId: string) => {
    loadEmailDetail(emailId);
  };

  // Human Approval Transition
  const handleApproveAction = async (actionId: string, notes?: string) => {
    setIsProcessingAction(true);
    try {
      await api.approveAction(actionId, notes);
      showToast(`Action approved. Gated execution unlocked.`, 'success');

      // Refresh current email detail and queue
      if (selectedEmailId) {
        const updated = await api.getEmail(selectedEmailId);
        setSelectedEmailDetail(updated);
      }
      const emailsRes = await api.getEmails();
      setEmails(emailsRes.emails || []);
    } catch (err: any) {
      showToast(err.message || 'Failed to approve action.', 'error');
    } finally {
      setIsProcessingAction(false);
    }
  };

  // Human Rejection Transition
  const handleRejectAction = async (actionId: string, reason: string) => {
    setIsProcessingAction(true);
    try {
      await api.rejectAction(actionId, reason);
      showToast(`Action rejected (Terminal state).`, 'info');

      // Refresh current email detail and queue
      if (selectedEmailId) {
        const updated = await api.getEmail(selectedEmailId);
        setSelectedEmailDetail(updated);
      }
      const emailsRes = await api.getEmails();
      setEmails(emailsRes.emails || []);
    } catch (err: any) {
      showToast(err.message || 'Failed to reject action.', 'error');
    } finally {
      setIsProcessingAction(false);
    }
  };

  // Simulated Execution Trigger (Gated strictly to APPROVED)
  const handleExecuteAction = async (actionId: string) => {
    setIsProcessingAction(true);
    try {
      const res = await api.executeAction(actionId);
      showToast(`Action executed via simulated driver: ${res.action_type}`, 'success');

      // Refresh current email detail and queue
      if (selectedEmailId) {
        const updated = await api.getEmail(selectedEmailId);
        setSelectedEmailDetail(updated);
      }
      const emailsRes = await api.getEmails();
      setEmails(emailsRes.emails || []);
    } catch (err: any) {
      showToast(err.message || 'Failed to execute action.', 'error');
    } finally {
      setIsProcessingAction(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#080c14] text-slate-100 flex flex-col font-sans">
      {/* Persistent Global Header */}
      <Header
        celestoStatus={celestoStatus}
        backendOnline={backendOnline}
        onRefresh={loadDashboardData}
        onOpenTelemetry={() => setIsTelemetryOpen(true)}
        isRefreshing={isRefreshing}
      />

      {/* Main Console Workspace */}
      <main className="flex-1 max-w-[1720px] w-full mx-auto px-4 py-4 space-y-4">
        {/* Offline Alert if Backend Offline */}
        {!backendOnline && (
          <div className="p-4 rounded-lg bg-rose-950/40 border border-rose-800 text-rose-200 flex items-center justify-between font-mono text-xs shadow-lg">
            <div className="flex items-center gap-3">
              <ServerOff className="w-5 h-5 text-rose-400 shrink-0" />
              <div>
                <p className="font-bold text-rose-300">
                  Backend unavailable — start the FastAPI server.
                </p>
                <p className="text-[11px] text-rose-400/80">
                  Run: <code>.\.venv\Scripts\python.exe -m uvicorn backend.app.main:app --reload</code>
                </p>
              </div>
            </div>
            <button
              onClick={loadDashboardData}
              className="px-3 py-1.5 rounded bg-rose-800 hover:bg-rose-700 text-white font-semibold text-xs flex items-center gap-1.5 cursor-pointer"
            >
              <RefreshCw className="w-3.5 h-3.5" />
              Retry Connection
            </button>
          </div>
        )}

        {/* Security KPI Metrics Strip */}
        <KpiMetrics emails={emails} isLoading={isLoadingEmails} />

        {/* Attack Simulator & Scenario Launcher Tray */}
        <ScenarioLauncher
          scenarios={scenarios}
          onTriggerScenario={handleTriggerScenario}
          isTriggering={isTriggering}
        />

        {/* Split Screen Workspace: Email Queue + Investigation & Action Console */}
        <div className="grid grid-cols-1 lg:grid-cols-12 gap-4 items-start">
          {/* Left Column: Email Queue (5 cols on lg) */}
          <div className="lg:col-span-5">
            <EmailQueue
              emails={emails}
              selectedEmailId={selectedEmailId}
              onSelectEmail={handleSelectEmail}
              isLoading={isLoadingEmails}
            />
          </div>

          {/* Right Column: Investigation View & Action Gate (7 cols on lg) */}
          <div className="lg:col-span-7">
            <InvestigationPanel
              email={selectedEmailDetail}
              isLoading={isLoadingDetail}
              onApproveAction={handleApproveAction}
              onRejectAction={handleRejectAction}
              onExecuteAction={handleExecuteAction}
              isProcessingAction={isProcessingAction}
            />
          </div>
        </div>
      </main>

      {/* Slide-over Telemetry Drawer */}
      <TelemetryDrawer
        isOpen={isTelemetryOpen}
        onClose={() => setIsTelemetryOpen(false)}
      />

      {/* Floating Status Toast Notification */}
      {toast && (
        <div className="fixed bottom-5 right-5 z-50 animate-in fade-in slide-in-from-bottom-3 duration-200">
          <div
            className={`flex items-center gap-2.5 px-4 py-3 rounded-lg border shadow-xl text-xs font-mono max-w-md ${
              toast.type === 'success'
                ? 'bg-emerald-950 border-emerald-600 text-emerald-200'
                : toast.type === 'error'
                ? 'bg-rose-950 border-rose-600 text-rose-200'
                : 'bg-slate-900 border-slate-700 text-slate-200'
            }`}
          >
            {toast.type === 'success' && <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0" />}
            {toast.type === 'error' && <AlertCircle className="w-4 h-4 text-rose-400 shrink-0" />}
            {toast.type === 'info' && <Info className="w-4 h-4 text-cyan-400 shrink-0" />}
            <span className="flex-1">{toast.message}</span>
            <button
              onClick={() => setToast(null)}
              className="p-1 hover:bg-black/20 rounded cursor-pointer text-slate-400 hover:text-white"
            >
              <X className="w-3.5 h-3.5" />
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

export default App;
