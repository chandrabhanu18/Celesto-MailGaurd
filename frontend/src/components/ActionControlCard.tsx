import React, { useState } from 'react';
import {
  Lock,
  Unlock,
  CheckCircle2,
  XCircle,
  Play,
  AlertTriangle,
  ShieldCheck,
  Cpu,
} from 'lucide-react';
import type { ActionProposalResponse } from '../types';

interface ActionControlCardProps {
  action: ActionProposalResponse;
  onApprove: (actionId: string, notes?: string) => Promise<void>;
  onReject: (actionId: string, reason: string) => Promise<void>;
  onExecute: (actionId: string) => Promise<void>;
  isProcessing: boolean;
}

export const ActionControlCard: React.FC<ActionControlCardProps> = ({
  action,
  onApprove,
  onReject,
  onExecute,
  isProcessing,
}) => {
  const [rejecting, setRejecting] = useState<boolean>(false);
  const [rejectionReason, setRejectionReason] = useState<string>('');
  const [rejectError, setRejectError] = useState<string | null>(null);

  const handleConfirmReject = async () => {
    if (!rejectionReason.trim()) {
      setRejectError('A valid rejection reason is strictly required.');
      return;
    }
    setRejectError(null);
    await onReject(action.id, rejectionReason.trim());
    setRejecting(false);
    setRejectionReason('');
  };

  const getRiskColor = (risk: string) => {
    switch (risk.toUpperCase()) {
      case 'CRITICAL':
        return 'bg-rose-950 text-rose-300 border-rose-700';
      case 'HIGH':
        return 'bg-amber-950 text-amber-300 border-amber-700';
      case 'MEDIUM':
        return 'bg-yellow-950 text-yellow-300 border-yellow-700';
      default:
        return 'bg-emerald-950 text-emerald-300 border-emerald-700';
    }
  };

  return (
    <div className="bg-[#0b101b] border border-slate-800 rounded-lg overflow-hidden">
      {/* Deterministic Policy Section Header */}
      <div className="bg-gradient-to-r from-blue-950/60 to-slate-900 px-4 py-3 border-b border-slate-800 flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-cyan-400" />
          <div>
            <h3 className="text-xs font-bold text-white uppercase tracking-wider font-mono">
              DETERMINISTIC GATEKEEPER
            </h3>
            <p className="text-[10px] text-cyan-400/80 font-mono">
              Policy engine, not the LLM, determines the executable proposal.
            </p>
          </div>
        </div>

        {/* State Badge */}
        <div className="font-mono text-xs">
          {action.state === 'PENDING_APPROVAL' && (
            <span className="px-2.5 py-1 rounded bg-yellow-950 text-yellow-300 border border-yellow-600 flex items-center gap-1.5 font-bold shadow-[0_0_10px_rgba(234,179,8,0.2)]">
              <Lock className="w-3.5 h-3.5 text-yellow-400" />
              PENDING APPROVAL
            </span>
          )}
          {action.state === 'APPROVED' && (
            <span className="px-2.5 py-1 rounded bg-blue-950 text-blue-300 border border-blue-600 flex items-center gap-1.5 font-bold shadow-[0_0_10px_rgba(59,130,246,0.2)]">
              <Unlock className="w-3.5 h-3.5 text-blue-400" />
              APPROVED (READY)
            </span>
          )}
          {action.state === 'REJECTED' && (
            <span className="px-2.5 py-1 rounded bg-slate-900 text-slate-400 border border-slate-700 flex items-center gap-1.5 font-semibold">
              <XCircle className="w-3.5 h-3.5 text-slate-400" />
              REJECTED (TERMINAL)
            </span>
          )}
          {action.state === 'EXECUTED' && (
            <span className="px-2.5 py-1 rounded bg-emerald-950 text-emerald-300 border border-emerald-600 flex items-center gap-1.5 font-bold shadow-[0_0_10px_rgba(16,185,129,0.2)]">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
              SIMULATED EXECUTION
            </span>
          )}
          {action.state === 'FAILED' && (
            <span className="px-2.5 py-1 rounded bg-rose-950 text-rose-300 border border-rose-700 flex items-center gap-1.5 font-bold">
              <AlertTriangle className="w-3.5 h-3.5 text-rose-400" />
              EXECUTION FAILED
            </span>
          )}
        </div>
      </div>

      {/* Proposal Details */}
      <div className="p-4 space-y-3">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 text-xs font-mono">
          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase block">Policy Rule</span>
            <span className="font-semibold text-slate-200">{action.policy_rule}</span>
          </div>
          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase block">Action Type</span>
            <span className="font-semibold text-cyan-300">{action.action_type}</span>
          </div>
          <div className="p-2 rounded bg-slate-900/60 border border-slate-800">
            <span className="text-[10px] text-slate-500 uppercase block">Risk Level</span>
            <span className={`inline-block px-1.5 py-0.2 rounded font-bold border ${getRiskColor(action.risk_level)}`}>
              {action.risk_level}
            </span>
          </div>
        </div>

        {/* Reason / Policy Justification */}
        <div className="p-2.5 rounded bg-slate-900/40 border border-slate-800 text-xs">
          <span className="text-[10px] font-mono text-slate-500 uppercase block mb-1">
            Policy Justification
          </span>
          <p className="text-slate-300">{action.reason}</p>
        </div>

        {/* Payload Snapshot if Available */}
        {action.payload && Object.keys(action.payload).length > 0 && (
          <div className="p-2.5 rounded bg-slate-955 border border-slate-800/80 font-mono text-xs">
            <span className="text-[10px] text-slate-500 uppercase block mb-1">Action Payload</span>
            <pre className="text-slate-400 text-[11px] overflow-x-auto p-1.5 bg-slate-900/60 rounded">
              {JSON.stringify(action.payload, null, 2)}
            </pre>
          </div>
        )}

        {/* Rejection Details if Rejected */}
        {action.state === 'REJECTED' && (
          <div className="p-3 rounded bg-rose-950/30 border border-rose-800/50 text-xs font-mono">
            <div className="flex items-center gap-1.5 text-rose-400 font-semibold mb-1">
              <XCircle className="w-4 h-4" />
              <span>TERMINAL STATE: Action Proposal Rejected</span>
            </div>
            <p className="text-rose-200">
              <span className="text-slate-400">Rejection Reason: </span>
              {action.rejection_reason || 'No reason specified.'}
            </p>
            {action.rejected_at && (
              <p className="text-[10px] text-slate-500 mt-1">
                Rejected at {action.rejected_at}
              </p>
            )}
          </div>
        )}

        {/* Execution Output if Executed */}
        {action.state === 'EXECUTED' && (
          <div className="p-3.5 rounded bg-emerald-950/20 border border-emerald-700/60 text-xs font-mono">
            <div className="flex items-center gap-2 text-emerald-400 font-bold mb-1">
              <Cpu className="w-4 h-4" />
              <span>SIMULATED EXECUTION</span>
            </div>
            <p className="text-emerald-300 font-sans text-xs mb-2">
              "No live Gmail, Calendar, or Social APIs were contacted."
            </p>
            {action.execution_result && (
              <pre className="text-emerald-200/90 text-[11px] p-2 bg-emerald-950/40 rounded border border-emerald-900 overflow-x-auto">
                {JSON.stringify(action.execution_result, null, 2)}
              </pre>
            )}
            {action.executed_at && (
              <p className="text-[10px] text-slate-500 mt-2">
                Executed via simulated driver at {action.executed_at}
              </p>
            )}
          </div>
        )}

        {/* Rejection Modal / Inline Form */}
        {rejecting && (
          <div className="p-3 rounded border border-rose-800 bg-rose-950/40 space-y-2">
            <label className="text-xs font-semibold text-rose-300 font-mono block">
              Specify Reason for Human Rejection (Mandatory):
            </label>
            <textarea
              value={rejectionReason}
              onChange={(e) => {
                setRejectionReason(e.target.value);
                setRejectError(null);
              }}
              placeholder="e.g. False positive: legitimate security incident response exercise."
              rows={2}
              className="w-full text-xs bg-slate-900 border border-slate-700 rounded p-2 text-slate-200 placeholder-slate-500 focus:outline-none focus:border-rose-500 font-sans"
            />
            {rejectError && <p className="text-xs text-rose-400 font-mono">{rejectError}</p>}
            <div className="flex items-center gap-2 justify-end">
              <button
                onClick={() => {
                  setRejecting(false);
                  setRejectError(null);
                }}
                disabled={isProcessing}
                className="px-3 py-1 text-xs rounded border border-slate-700 bg-slate-800 hover:bg-slate-700 text-slate-300 font-mono cursor-pointer"
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmReject}
                disabled={isProcessing || !rejectionReason.trim()}
                className="px-3 py-1 text-xs rounded bg-rose-600 hover:bg-rose-500 text-white font-semibold font-mono cursor-pointer disabled:opacity-50"
              >
                {isProcessing ? 'Rejecting...' : 'Confirm Rejection'}
              </button>
            </div>
          </div>
        )}

        {/* Human Authorization Action Bar */}
        <div className="pt-3 border-t border-slate-800 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          {/* Status Message */}
          <div className="text-xs font-mono">
            {action.state === 'PENDING_APPROVAL' && (
              <span className="text-amber-400 flex items-center gap-1.5 font-semibold">
                <Lock className="w-3.5 h-3.5" />
                Execution locked — explicit human approval required.
              </span>
            )}
            {action.state === 'APPROVED' && (
              <span className="text-blue-400 flex items-center gap-1.5 font-semibold">
                <Unlock className="w-3.5 h-3.5" />
                Human authorization granted. Ready for simulated execution.
              </span>
            )}
            {action.state === 'REJECTED' && (
              <span className="text-slate-500">
                Action proposal is rejected (Terminal state). Execution blocked.
              </span>
            )}
            {action.state === 'EXECUTED' && (
              <span className="text-emerald-400 flex items-center gap-1.5">
                <CheckCircle2 className="w-3.5 h-3.5" />
                Simulated execution complete. Replay protection active.
              </span>
            )}
          </div>

          {/* Buttons */}
          <div className="flex items-center gap-2">
            {action.state === 'PENDING_APPROVAL' && !rejecting && (
              <>
                <button
                  onClick={() => setRejecting(true)}
                  disabled={isProcessing}
                  className="px-3.5 py-1.5 rounded border border-rose-800/80 bg-rose-950/60 hover:bg-rose-900 text-rose-300 font-mono text-xs font-semibold cursor-pointer transition-colors disabled:opacity-50"
                >
                  Reject Action
                </button>
                <button
                  onClick={() => onApprove(action.id)}
                  disabled={isProcessing}
                  className="px-4 py-1.5 rounded bg-blue-600 hover:bg-blue-500 text-white font-mono text-xs font-semibold shadow-[0_0_12px_rgba(59,130,246,0.3)] cursor-pointer transition-colors disabled:opacity-50 flex items-center gap-1.5"
                >
                  <Unlock className="w-3.5 h-3.5" />
                  Approve Action
                </button>
              </>
            )}

            {/* Execute Button */}
            {action.state === 'APPROVED' && (
              <button
                onClick={() => onExecute(action.id)}
                disabled={isProcessing}
                className="px-5 py-2 rounded bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white font-mono text-xs font-bold shadow-[0_0_15px_rgba(16,185,129,0.3)] cursor-pointer transition-all disabled:opacity-50 flex items-center gap-2"
              >
                <Play className="w-3.5 h-3.5 fill-current" />
                Execute Action (Simulated Driver)
              </button>
            )}

            {/* Disabled Execute in PENDING_APPROVAL */}
            {action.state === 'PENDING_APPROVAL' && (
              <button
                disabled
                title="Action must be approved before execution can be requested."
                className="px-3 py-1.5 rounded border border-slate-800 bg-slate-900 text-slate-600 font-mono text-xs flex items-center gap-1.5 cursor-not-allowed opacity-60"
              >
                <Lock className="w-3.5 h-3.5" />
                Execute (Locked)
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};
