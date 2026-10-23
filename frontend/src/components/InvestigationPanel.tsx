import React from 'react';
import {
  Terminal,
  Calendar,
  Cpu,
  Link,
  Eye,
  Sparkles,
  CheckCircle,
  Radio,
} from 'lucide-react';
import type { EmailDetailResponse } from '../types';
import { ActionControlCard } from './ActionControlCard';

interface InvestigationPanelProps {
  email: EmailDetailResponse | null;
  isLoading: boolean;
  onApproveAction: (actionId: string, notes?: string) => Promise<void>;
  onRejectAction: (actionId: string, reason: string) => Promise<void>;
  onExecuteAction: (actionId: string) => Promise<void>;
  isProcessingAction: boolean;
}

export const InvestigationPanel: React.FC<InvestigationPanelProps> = ({
  email,
  isLoading,
  onApproveAction,
  onRejectAction,
  onExecuteAction,
  isProcessingAction,
}) => {
  if (isLoading) {
    return (
      <div className="bg-[#0b101b] border border-cyan-800/60 rounded-lg p-8 flex flex-col items-center justify-center h-[740px] text-cyan-300 font-mono text-xs">
        <span className="animate-spin text-3xl text-cyan-400 mb-3">⚙️</span>
        <span className="font-bold tracking-wider uppercase text-sm">Quarantine Isolation Active</span>
        <span className="text-slate-400 text-[11px] mt-1">Executing sandbox inspector and synchronizing investigation data...</span>
      </div>
    );
  }

  if (!email) {
    return (
      <div className="bg-[#0b101b] border border-slate-800 rounded-lg p-8 flex flex-col items-center justify-center h-[740px] text-slate-500 font-mono text-center">
        <Eye className="w-12 h-12 text-slate-700 mb-3" />
        <h3 className="text-sm font-semibold text-slate-300 uppercase tracking-wider">No Active Investigation</h3>
        <p className="text-xs text-slate-500 mt-2 max-w-sm">
          Select an incoming email from the queue on the left, or click <span className="text-cyan-400 font-semibold">"Trigger Quarantine Pipeline"</span> above to launch an attack or benign scenario.
        </p>
      </div>
    );
  }

  const staticInsp = email.static_inspection;
  const analysis = email.latest_analysis;
  const telemetry = email.telemetry;
  const isFallback = telemetry?.provider_mode === 'DEMO_FALLBACK';

  return (
    <div className="bg-[#0b101b] border border-slate-800 rounded-lg flex flex-col h-[740px] overflow-hidden">
      {/* Top Prominent Callout Banner: Active Target Invariant */}
      <div className="p-3 bg-gradient-to-r from-cyan-950/80 via-slate-900 to-slate-950 border-b border-cyan-500/50 flex flex-col sm:flex-row sm:items-center justify-between gap-2 shadow-[0_4px_12px_rgba(6,182,212,0.1)]">
        <div className="flex items-center gap-2.5">
          <span className="relative flex h-3.5 w-3.5">
            <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-cyan-400 opacity-75"></span>
            <span className="relative inline-flex rounded-full h-3.5 w-3.5 bg-cyan-500"></span>
          </span>
          <div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] font-mono uppercase tracking-widest text-cyan-400 font-bold flex items-center gap-1">
                <Radio className="w-3 h-3 text-cyan-400 animate-pulse" />
                ACTIVE INVESTIGATION
              </span>
              {email.scenario_id && (
                <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-cyan-950 text-cyan-300 border border-cyan-700/80 font-bold">
                  {email.scenario_id}
                </span>
              )}
            </div>
            <h2 className="text-sm font-bold text-white font-mono leading-tight mt-0.5">
              Investigating: {email.subject || '(No Subject)'}
            </h2>
          </div>
        </div>
        <div className="text-left sm:text-right text-[11px] font-mono text-slate-400 shrink-0">
          <div>
            Sender: <span className="text-slate-200 font-semibold">{email.sender}</span>
          </div>
          <div className="text-[10px] text-slate-500">
            Canonical Email ID: <code className="text-cyan-400">{email.id.slice(0, 18)}...</code>
          </div>
        </div>
      </div>

      {/* Main Investigation Content Scroll Area */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* ======================================================== */}
        {/* SECTION 1: EMAIL METADATA & UNTRUSTED BODY */}
        {/* ======================================================== */}
        <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/40">
          <div className="flex items-center justify-between mb-2">
            <span className="text-[11px] font-mono font-bold uppercase text-slate-400">
              1. Email Envelope & Fenced Text
            </span>
            <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800/60 font-semibold">
              Untrusted Passive Content
            </span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-2 text-xs font-mono mb-3 bg-slate-900/60 p-2.5 rounded border border-slate-800">
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Sender</span>
              <span className="text-slate-200 font-semibold truncate block">{email.sender}</span>
            </div>
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Recipient</span>
              <span className="text-slate-200 truncate block">{email.recipient}</span>
            </div>
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Subject</span>
              <span className="text-white font-semibold truncate block">{email.subject}</span>
            </div>
            <div>
              <span className="text-slate-500 text-[10px] uppercase block">Date</span>
              <span className="text-slate-400 block">{email.date_str || email.created_at}</span>
            </div>
          </div>

          {/* Fenced Untrusted Body Display */}
          <div className="relative">
            <div className="text-[10px] font-mono text-slate-400 mb-1 flex items-center justify-between">
              <span>Fenced Body Text (&lt;untrusted_email_body&gt;)</span>
              <span className="text-slate-500">Active scripts stripped</span>
            </div>
            <div className="bg-[#050811] border border-slate-800/90 rounded p-3 text-xs font-mono text-slate-300 whitespace-pre-wrap max-h-40 overflow-y-auto select-text leading-relaxed">
              {email.sanitized_text || '(Empty text payload)'}
            </div>
          </div>
        </div>

        {/* ======================================================== */}
        {/* SECTION 2: STATIC INSPECTION (PHASE 2A) */}
        {/* ======================================================== */}
        <div className="border border-slate-800 rounded-lg p-3 bg-slate-950/40">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-1.5">
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span className="text-[11px] font-mono font-bold uppercase text-slate-400">
                2. Phase 2A Static Inspection & Celesto Telemetry
              </span>
            </div>
            <span
              className={`text-[10px] font-mono px-2 py-0.5 rounded border font-semibold ${
                isFallback
                  ? 'bg-amber-950 text-amber-300 border-amber-700'
                  : 'bg-emerald-950 text-emerald-300 border-emerald-700'
              }`}
            >
              {isFallback ? 'DEMO FALLBACK (Subprocess)' : 'REAL CELESTO MICROVM'}
            </span>
          </div>

          {/* Telemetry Strip */}
          {telemetry && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-[11px] font-mono mb-3 bg-slate-900/60 p-2 rounded border border-slate-800">
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Sandbox ID</span>
                <span className="text-slate-300 truncate block">{telemetry.sandbox_id}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Network Policy</span>
                <span className="text-rose-400 font-bold block">{telemetry.network_mode.toUpperCase()}</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Execution Time</span>
                <span className="text-slate-300 block">{telemetry.execution_time_ms} ms</span>
              </div>
              <div>
                <span className="text-slate-500 text-[10px] uppercase block">Exit Code</span>
                <span className="text-emerald-400 font-bold block">{telemetry.exit_code}</span>
              </div>
            </div>
          )}

          {/* Static Risk & Heuristic Indicator Tags */}
          <div className="space-y-2 text-xs font-mono">
            <div className="flex items-center justify-between p-2 rounded bg-slate-900 border border-slate-800">
              <span className="text-slate-400">Static Risk Score:</span>
              <div className="flex items-center gap-2">
                <span className="font-bold text-white text-sm">
                  {staticInsp.static_risk_score.toFixed(2)} / 1.00
                </span>
                <span
                  className={`px-2 py-0.5 rounded text-[10px] font-bold ${
                    staticInsp.static_risk_label === 'CRITICAL'
                      ? 'bg-rose-950 text-rose-300 border border-rose-700'
                      : staticInsp.static_risk_label === 'SUSPICIOUS'
                      ? 'bg-amber-950 text-amber-300 border border-amber-700'
                      : 'bg-emerald-950 text-emerald-300 border border-emerald-700'
                  }`}
                >
                  {staticInsp.static_risk_label}
                </span>
              </div>
            </div>

            {/* Heuristic Flags List */}
            <div className="flex flex-wrap gap-1.5">
              {staticInsp.has_prompt_injection && (
                <span className="px-2 py-1 rounded bg-rose-950/80 text-rose-300 border border-rose-700 text-[10px] font-bold flex items-center gap-1">
                  <Terminal className="w-3 h-3 text-rose-400" />
                  Prompt Injection Pattern Detected
                </span>
              )}
              {staticInsp.has_zero_width_chars && (
                <span className="px-2 py-1 rounded bg-purple-950/80 text-purple-300 border border-purple-700 text-[10px] font-bold flex items-center gap-1">
                  <Eye className="w-3 h-3 text-purple-400" />
                  Invisible Zero-Width Characters
                </span>
              )}
              {staticInsp.has_suspicious_homoglyph && (
                <span className="px-2 py-1 rounded bg-amber-950/80 text-amber-300 border border-amber-700 text-[10px] font-bold flex items-center gap-1">
                  <Link className="w-3 h-3 text-amber-400" />
                  Homoglyph / Typosquatting Brand Link
                </span>
              )}
              {staticInsp.has_ip_url && (
                <span className="px-2 py-1 rounded bg-amber-950/80 text-amber-300 border border-amber-700 text-[10px] font-bold flex items-center gap-1">
                  <Link className="w-3 h-3 text-amber-400" />
                  Raw IPv4 Address Link
                </span>
              )}
              {!staticInsp.has_prompt_injection &&
                !staticInsp.has_zero_width_chars &&
                !staticInsp.has_suspicious_homoglyph &&
                !staticInsp.has_ip_url && (
                  <span className="px-2 py-1 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800 text-[10px] font-medium flex items-center gap-1">
                    <CheckCircle className="w-3 h-3 text-emerald-400" />
                    Clean Static Heuristics — No Evasion Signatures
                  </span>
                )}
            </div>

            {/* Raw Indicators Details if any */}
            {staticInsp.threat_indicators && staticInsp.threat_indicators.length > 0 && (
              <div className="mt-2 space-y-1">
                {staticInsp.threat_indicators.map((ind: any, i: number) => (
                  <div
                    key={i}
                    className="p-1.5 rounded bg-slate-900/80 border border-slate-800 text-[11px] flex items-start gap-2 text-slate-300"
                  >
                    <span className="text-rose-400 font-bold uppercase text-[10px] mt-0.5 whitespace-nowrap">
                      [{ind.indicator_type || ind.severity || 'ALERT'}]
                    </span>
                    <span className="flex-1">{ind.description}</span>
                    {ind.matched_pattern && (
                      <span className="text-[10px] text-slate-500 font-mono">
                        "{ind.matched_pattern.slice(0, 40)}"
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>

        {/* ======================================================== */}
        {/* SECTION 3: AI ADVISORY EVALUATION (PHASE 2B) */}
        {/* ======================================================== */}
        <div className="border border-purple-900/50 rounded-lg p-3 bg-purple-950/10">
          {/* Header Banner */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 mb-2 pb-2 border-b border-purple-900/40">
            <div className="flex items-center gap-2">
              <Sparkles className="w-4 h-4 text-purple-400" />
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-mono font-bold uppercase text-purple-200">
                    3. AI Security & Urgency Advisory
                  </span>
                  <span className="px-1.5 py-0.2 rounded text-[9px] font-mono font-bold bg-purple-950 text-purple-300 border border-purple-600">
                    ADVISORY ONLY
                  </span>
                </div>
                <p className="text-[10px] text-purple-300/80 font-mono">
                  "AI analysis is probabilistic and does not authorize actions."
                </p>
              </div>
            </div>

            {analysis && (
              <span className="text-[10px] font-mono text-purple-300 bg-purple-950/80 px-2 py-0.5 rounded border border-purple-800">
                {analysis.provider.toUpperCase()} ({analysis.model})
              </span>
            )}
          </div>

          {analysis ? (
            <div className="space-y-3">
              {/* Classification Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs font-mono">
                <div className="p-2 rounded bg-slate-900/80 border border-purple-900/50">
                  <span className="text-[10px] text-slate-500 uppercase block">Threat Category</span>
                  <span className="font-bold text-purple-300">{analysis.threat_category}</span>
                </div>
                <div className="p-2 rounded bg-slate-900/80 border border-purple-900/50">
                  <span className="text-[10px] text-slate-500 uppercase block">Threat Level</span>
                  <span
                    className={`font-bold ${
                      analysis.threat_level === 'CRITICAL'
                        ? 'text-rose-400'
                        : analysis.threat_level === 'HIGH'
                        ? 'text-amber-400'
                        : 'text-emerald-400'
                    }`}
                  >
                    {analysis.threat_level}
                  </span>
                </div>
                <div className="p-2 rounded bg-slate-900/80 border border-purple-900/50">
                  <span className="text-[10px] text-slate-500 uppercase block">Confidence</span>
                  <span className="font-bold text-white">
                    {Math.round(analysis.confidence * 100)}%
                  </span>
                </div>
                <div className="p-2 rounded bg-slate-900/80 border border-purple-900/50">
                  <span className="text-[10px] text-slate-500 uppercase block">Urgency Rating</span>
                  <span className="font-bold text-yellow-300">{analysis.urgency} / 5</span>
                </div>
              </div>

              {/* Advisory Rationale */}
              <div className="p-2.5 rounded bg-slate-900/60 border border-purple-900/40 text-xs">
                <span className="text-[10px] font-mono text-purple-400 uppercase block mb-1">
                  Advisory Rationale:
                </span>
                <p className="text-slate-200 font-sans leading-relaxed">
                  {analysis.explanation}
                </p>
                <div className="mt-2 text-[11px] font-mono text-slate-400 flex items-center gap-1">
                  <span>Recommendation: </span>
                  <span className="font-bold text-purple-300">
                    {analysis.recommended_action}
                  </span>
                  <span className="text-slate-500 text-[10px]">
                    (Non-binding advisory recommendation)
                  </span>
                </div>
              </div>

              {/* Extracted Calendar Event if Present */}
              {analysis.calendar_event_detected && analysis.extracted_calendar_event && (
                <div className="p-3 rounded bg-cyan-950/20 border border-cyan-800/60 text-xs font-mono">
                  <div className="flex items-center gap-1.5 text-cyan-400 font-bold mb-2">
                    <Calendar className="w-4 h-4" />
                    <span>Actionable Calendar Event Detected</span>
                  </div>
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2 text-[11px]">
                    <div>
                      <span className="text-slate-500 block">Title</span>
                      <span className="text-white font-semibold">
                        {analysis.extracted_calendar_event.title}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Date & Time</span>
                      <span className="text-cyan-300">
                        {analysis.extracted_calendar_event.date} at{' '}
                        {analysis.extracted_calendar_event.start_time || 'Time TBD'}
                      </span>
                    </div>
                    {analysis.extracted_calendar_event.location && (
                      <div className="sm:col-span-2">
                        <span className="text-slate-500 block">Location / URL</span>
                        <span className="text-slate-300">
                          {analysis.extracted_calendar_event.location}
                        </span>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          ) : (
            <div className="p-4 text-center text-xs font-mono text-purple-400/80">
              No Phase 2B advisory analysis performed for this record.
            </div>
          )}
        </div>

        {/* ======================================================== */}
        {/* SECTION 4: DETERMINISTIC POLICY & ACTION GATING (PHASE 3) */}
        {/* ======================================================== */}
        <div>
          <span className="text-[11px] font-mono font-bold uppercase text-slate-400 mb-2 block">
            4. Phase 3 Policy Engine & Action Authorization
          </span>

          {email.actions && email.actions.length > 0 ? (
            <div className="space-y-3">
              {email.actions.map((act) => (
                <ActionControlCard
                  key={act.id}
                  action={act}
                  onApprove={onApproveAction}
                  onReject={onRejectAction}
                  onExecute={onExecuteAction}
                  isProcessing={isProcessingAction}
                />
              ))}
            </div>
          ) : (
            <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40 text-xs font-mono text-slate-400 text-center">
              <CheckCircle className="w-6 h-6 text-emerald-400 mx-auto mb-1.5" />
              <p className="font-semibold text-slate-300">
                Deterministic Policy Rule: BENIGN_NO_ACTION
              </p>
              <p className="text-[11px] text-slate-500 mt-0.5">
                Clean correspondence with low risk score does not generate disruptive action proposals.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};
