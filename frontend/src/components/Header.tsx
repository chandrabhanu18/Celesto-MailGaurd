import React from 'react';
import {
  Shield,
  Cpu,
  Lock,
  Terminal,
  Activity,
  AlertTriangle,
  RefreshCw,
  Sliders,
} from 'lucide-react';
import type { CelestoStatusResponse } from '../types';

interface HeaderProps {
  celestoStatus: CelestoStatusResponse | null;
  backendOnline: boolean;
  onRefresh: () => void;
  onOpenTelemetry: () => void;
  isRefreshing: boolean;
}

export const Header: React.FC<HeaderProps> = ({
  celestoStatus,
  backendOnline,
  onRefresh,
  onOpenTelemetry,
  isRefreshing,
}) => {
  const isRealCelesto = celestoStatus?.provider_mode === 'REAL_CELESTO';

  return (
    <header className="border-b border-slate-800 bg-[#0b101b]/95 backdrop-blur sticky top-0 z-40 px-6 py-3">
      <div className="flex flex-col lg:flex-row lg:items-center lg:justify-between gap-4">
        {/* Brand & Mission Statement */}
        <div className="flex items-center gap-3">
          <div className="p-2.5 rounded-lg bg-cyan-950/80 border border-cyan-500/40 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
            <Shield className="w-6 h-6" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h1 className="text-xl font-bold tracking-tight text-white font-mono">
                MailGuard
              </h1>
              <span className="text-[10px] font-semibold px-2 py-0.5 rounded bg-cyan-950/80 text-cyan-400 border border-cyan-800/80 uppercase tracking-wider">
                SOC v0.1
              </span>
              <span
                className={`flex items-center gap-1.5 text-xs px-2 py-0.5 rounded border ${
                  backendOnline
                    ? 'bg-emerald-950/60 border-emerald-800/80 text-emerald-400'
                    : 'bg-rose-950/60 border-rose-800/80 text-rose-400'
                }`}
              >
                <span
                  className={`w-1.5 h-1.5 rounded-full ${
                    backendOnline ? 'bg-emerald-400 animate-pulse' : 'bg-rose-500'
                  }`}
                />
                {backendOnline ? 'API CONNECTED' : 'BACKEND OFFLINE'}
              </span>
            </div>
            <p className="text-xs text-slate-400 font-sans mt-0.5">
              Personal AI Communication Gatekeeper —{' '}
              <span className="text-slate-300 font-mono text-[11px]">
                "Read automatically. Think safely. Act only with permission."
              </span>
            </p>
          </div>
        </div>

        {/* Persistent Security Posture Indicators */}
        <div className="flex flex-wrap items-center gap-2">
          {/* Celesto Provider Indicator */}
          <div
            className={`flex items-center gap-2 px-3 py-1.5 rounded border text-xs font-mono transition-colors ${
              isRealCelesto
                ? 'bg-emerald-950/50 border-emerald-700/60 text-emerald-300'
                : 'bg-amber-950/40 border-amber-700/60 text-amber-300'
            }`}
          >
            {isRealCelesto ? (
              <Cpu className="w-4 h-4 text-emerald-400" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-amber-400" />
            )}
            <div>
              <div className="flex items-center gap-1 text-[10px] uppercase tracking-wider text-slate-400">
                <span>Celesto Isolation</span>
              </div>
              <div className="font-semibold text-[11px] leading-tight">
                {isRealCelesto ? 'REAL CELESTO (MicroVM)' : 'DEMO FALLBACK'}
              </div>
              <div className="text-[9px] text-amber-400/80">
                {isRealCelesto ? 'Network: OFF' : 'SUBPROCESS SIMULATION'}
              </div>
            </div>
          </div>

          {/* Advisory LLM Indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded border border-purple-800/60 bg-purple-950/40 text-purple-200 text-xs font-mono">
            <Terminal className="w-4 h-4 text-purple-400" />
            <div>
              <div className="text-[10px] uppercase tracking-wider text-purple-400/80">
                Advisory LLM
              </div>
              <div className="font-semibold text-[11px] leading-tight">
                MOCK / ZERO TOOLS
              </div>
              <div className="text-[9px] text-purple-300/70">
                Probabilistic / Untrusted
              </div>
            </div>
          </div>

          {/* Deterministic Policy Indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded border border-blue-800/60 bg-blue-950/40 text-blue-200 text-xs font-mono">
            <Sliders className="w-4 h-4 text-blue-400" />
            <div>
              <div className="text-[10px] uppercase tracking-wider text-blue-400/80">
                Policy Engine
              </div>
              <div className="font-semibold text-[11px] leading-tight">
                DETERMINISTIC
              </div>
              <div className="text-[9px] text-blue-300/70">
                Rules &gt; LLM Advice
              </div>
            </div>
          </div>

          {/* Simulated Execution Indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded border border-cyan-800/60 bg-cyan-950/40 text-cyan-200 text-xs font-mono">
            <Activity className="w-4 h-4 text-cyan-400" />
            <div>
              <div className="text-[10px] uppercase tracking-wider text-cyan-400/80">
                Execution Driver
              </div>
              <div className="font-semibold text-[11px] leading-tight">
                SIMULATED ONLY
              </div>
              <div className="text-[9px] text-cyan-300/70">
                Zero External Side Effects
              </div>
            </div>
          </div>

          {/* Mandatory Human Gate Indicator */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded border border-rose-800/60 bg-rose-950/40 text-rose-200 text-xs font-mono">
            <Lock className="w-4 h-4 text-rose-400" />
            <div>
              <div className="text-[10px] uppercase tracking-wider text-rose-400/80">
                Human Gate
              </div>
              <div className="font-semibold text-[11px] leading-tight">
                MANDATORY
              </div>
              <div className="text-[9px] text-rose-300/70">
                Approval Strictly Required
              </div>
            </div>
          </div>

          {/* Utility Actions */}
          <div className="flex items-center gap-1.5 pl-2 border-l border-slate-800">
            <button
              onClick={onOpenTelemetry}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-xs font-mono text-slate-300 transition-colors cursor-pointer"
              title="View Celesto Telemetry Stream"
            >
              <Cpu className="w-3.5 h-3.5 text-cyan-400" />
              <span>Telemetry</span>
            </button>
            <button
              onClick={onRefresh}
              disabled={isRefreshing}
              className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-700 text-slate-300 transition-colors disabled:opacity-50 cursor-pointer"
              title="Refresh Data"
            >
              <RefreshCw className={`w-4 h-4 ${isRefreshing ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
          </div>
        </div>
      </div>
    </header>
  );
};
