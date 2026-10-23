import React, { useEffect, useState } from 'react';
import {
  X,
  Cpu,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react';
import type { CelestoTelemetryItem } from '../types';
import { api } from '../services/api';

interface TelemetryDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

export const TelemetryDrawer: React.FC<TelemetryDrawerProps> = ({
  isOpen,
  onClose,
}) => {
  const [telemetry, setTelemetry] = useState<CelestoTelemetryItem[]>([]);
  const [isLoading, setIsLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);

  const fetchTelemetry = async () => {
    setIsLoading(true);
    setError(null);
    try {
      const data = await api.getCelestoTelemetry(50);
      setTelemetry(data);
    } catch (e: any) {
      setError(e.message || 'Failed to load Celesto telemetry.');
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchTelemetry();
    }
  }, [isOpen]);

  if (!isOpen) return null;

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex justify-end animate-in fade-in duration-200">
      <div className="w-full max-w-2xl bg-[#080c14] border-l border-slate-800 h-full flex flex-col shadow-2xl">
        {/* Header */}
        <div className="p-4 border-b border-slate-800 flex items-center justify-between bg-slate-950">
          <div className="flex items-center gap-2">
            <Cpu className="w-5 h-5 text-cyan-400" />
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider font-mono">
                Celesto Sandbox Execution Telemetry
              </h2>
              <p className="text-[11px] text-slate-400">
                Audited sandbox runs, microVM lifecycle events, and network confinement checks.
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button
              onClick={fetchTelemetry}
              disabled={isLoading}
              className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
              title="Refresh Telemetry"
            >
              <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin text-cyan-400' : ''}`} />
            </button>
            <button
              onClick={onClose}
              className="p-1.5 rounded bg-slate-900 hover:bg-slate-800 border border-slate-800 text-slate-400 hover:text-white transition-colors cursor-pointer"
              title="Close Drawer"
            >
              <X className="w-4 h-4" />
            </button>
          </div>
        </div>

        {/* Informational Transparency Alert */}
        <div className="px-4 py-2.5 bg-amber-950/30 border-b border-amber-800/40 text-xs font-mono text-amber-300 flex items-start gap-2">
          <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
          <div>
            <span className="font-bold">ISOLATION INTEGRITY NOTICE: </span>
            <span>
              Runs with provider <code className="text-amber-200 font-bold">DEMO_FALLBACK</code> run in a local subprocess with scrubbed environment and are NOT virtualized in a microVM. Real Celesto microVMs require <code className="text-amber-200">CELESTO_API_KEY</code>.
            </span>
          </div>
        </div>

        {/* Telemetry Stream List */}
        <div className="flex-1 overflow-y-auto p-4 space-y-3 font-mono">
          {isLoading && telemetry.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-48 text-slate-500 text-xs">
              <span className="animate-spin text-cyan-400 mb-2">⚙️</span>
              Loading telemetry log records...
            </div>
          ) : error ? (
            <div className="p-3 rounded bg-rose-950/40 border border-rose-800 text-rose-300 text-xs">
              {error}
            </div>
          ) : telemetry.length === 0 ? (
            <div className="text-center text-slate-500 text-xs py-12">
              No telemetry events recorded yet. Run a scenario to see isolated executions.
            </div>
          ) : (
            telemetry.map((tele) => {
              const isFallback = tele.provider_mode === 'DEMO_FALLBACK';
              return (
                <div
                  key={tele.id}
                  className={`p-3 rounded-lg border text-xs transition-colors ${
                    isFallback
                      ? 'bg-slate-900/40 border-amber-800/40 hover:border-amber-700/60'
                      : 'bg-emerald-950/20 border-emerald-800/50 hover:border-emerald-700'
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span
                      className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                        isFallback
                          ? 'bg-amber-950 text-amber-300 border-amber-700'
                          : 'bg-emerald-950 text-emerald-300 border-emerald-600'
                      }`}
                    >
                      {isFallback ? 'DEMO_FALLBACK (Subprocess)' : 'REAL_CELESTO (MicroVM)'}
                    </span>
                    <span className="text-[10px] text-slate-500">
                      {tele.created_at ? tele.created_at.slice(0, 19).replace('T', ' ') : 'N/A'}
                    </span>
                  </div>

                  <div className="text-slate-200 font-semibold mb-2 line-clamp-1">
                    {tele.email_subject || 'Simulated Email Payload'}
                  </div>

                  <div className="grid grid-cols-2 gap-2 text-[11px] bg-slate-950/70 p-2 rounded border border-slate-800/80 mb-2">
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Sandbox ID</span>
                      <span className="text-slate-300 text-[10px] truncate block" title={tele.sandbox_id}>
                        {tele.sandbox_id}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Network Egress</span>
                      <span className="text-rose-400 font-bold block">
                        mode='{tele.network_mode}' (DENIED)
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Execution Duration</span>
                      <span className="text-slate-300 block">{tele.execution_time_ms} ms</span>
                    </div>
                    <div>
                      <span className="text-slate-500 text-[10px] uppercase block">Exit Code</span>
                      <span className="text-emerald-400 font-bold block">{tele.exit_code} (SUCCESS)</span>
                    </div>
                  </div>

                  {tele.indicators && tele.indicators.length > 0 && (
                    <div className="text-[10px] space-y-1">
                      <span className="text-slate-500 uppercase block">Threat Indicators Detected:</span>
                      <div className="flex flex-wrap gap-1">
                        {tele.indicators.map((ind: any, idx: number) => (
                          <span
                            key={idx}
                            className="px-1.5 py-0.5 rounded bg-rose-950/80 text-rose-300 border border-rose-800"
                          >
                            {ind.indicator_type || ind.severity || 'SIGNAL'}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {tele.error_message && (
                    <div className="mt-2 text-[10px] text-rose-400 p-1.5 bg-rose-950/30 rounded border border-rose-900">
                      Error: {tele.error_message}
                    </div>
                  )}
                </div>
              );
            })
          )}
        </div>
      </div>
    </div>
  );
};
