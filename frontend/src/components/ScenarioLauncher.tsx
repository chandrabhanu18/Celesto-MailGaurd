import React, { useState } from 'react';
import {
  Play,
  Zap,
  ShieldAlert,
  Terminal,
  Calendar,
  AlertTriangle,
  FileCode,
  Newspaper,
  CheckCircle,
  EyeOff,
  UserCheck,
  Flame,
} from 'lucide-react';
import type { SimulationScenarioMeta, SimulationTriggerResponse } from '../types';

interface ScenarioLauncherProps {
  scenarios: SimulationScenarioMeta[];
  onTriggerScenario: (
    scenarioId: string,
    runLlm: boolean,
    proposeActions: boolean
  ) => Promise<SimulationTriggerResponse | null>;
  isTriggering: boolean;
}

export const ScenarioLauncher: React.FC<ScenarioLauncherProps> = ({
  scenarios,
  onTriggerScenario,
  isTriggering,
}) => {
  const [selectedScenarioId, setSelectedScenarioId] = useState<string>('scenario_direct_injection');
  const [runLlm, setRunLlm] = useState<boolean>(true);
  const [proposeActions, setProposeActions] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<'all' | 'attacks' | 'benign'>('all');

  const filteredScenarios = scenarios.filter((s) => {
    if (activeTab === 'attacks') return s.category === 'PHISHING' || s.category === 'PROMPT_INJECTION';
    if (activeTab === 'benign') return s.category !== 'PHISHING' && s.category !== 'PROMPT_INJECTION';
    return true;
  });

  const getScenarioIcon = (scenario: SimulationScenarioMeta) => {
    switch (scenario.scenario_id) {
      case 'scenario_direct_injection':
        return <Terminal className="w-4 h-4 text-rose-400" />;
      case 'scenario_hidden_injection':
        return <EyeOff className="w-4 h-4 text-purple-400" />;
      case 'scenario_phishing':
        return <Flame className="w-4 h-4 text-amber-400" />;
      case 'scenario_interview':
        return <Calendar className="w-4 h-4 text-cyan-400" />;
      case 'scenario_assessment':
        return <FileCode className="w-4 h-4 text-blue-400" />;
      case 'scenario_deadline':
        return <AlertTriangle className="w-4 h-4 text-yellow-400" />;
      case 'scenario_recruiter':
        return <UserCheck className="w-4 h-4 text-emerald-400" />;
      case 'scenario_newsletter':
        return <Newspaper className="w-4 h-4 text-slate-400" />;
      default:
        return <CheckCircle className="w-4 h-4 text-slate-400" />;
    }
  };

  const handleLaunch = () => {
    if (!selectedScenarioId) return;
    onTriggerScenario(selectedScenarioId, runLlm, proposeActions);
  };

  const currentScenario = scenarios.find((s) => s.scenario_id === selectedScenarioId);

  return (
    <div className="bg-[#0b101b] border border-slate-800 rounded-lg p-4">
      {/* Header & Tabs */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-3 pb-3 border-b border-slate-800/80">
        <div className="flex items-center gap-2">
          <div className="p-1.5 rounded bg-cyan-950/60 border border-cyan-800/60 text-cyan-400">
            <Zap className="w-4 h-4" />
          </div>
          <div>
            <h2 className="text-sm font-semibold text-white tracking-wide font-mono">
              Quarantine Attack & Scenario Simulator
            </h2>
            <p className="text-[11px] text-slate-400">
              Select one of the 9 pre-loaded fixtures to evaluate through the Celesto MicroVM / Subprocess quarantine pipeline.
            </p>
          </div>
        </div>

        {/* Tab Filter */}
        <div className="flex items-center gap-1 bg-slate-900/90 p-1 rounded border border-slate-800 text-xs font-mono">
          <button
            onClick={() => setActiveTab('all')}
            className={`px-2.5 py-1 rounded transition-colors ${
              activeTab === 'all'
                ? 'bg-slate-800 text-white font-medium shadow-sm'
                : 'text-slate-400 hover:text-slate-200'
            }`}
          >
            All (9)
          </button>
          <button
            onClick={() => setActiveTab('attacks')}
            className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1 ${
              activeTab === 'attacks'
                ? 'bg-rose-950/80 text-rose-300 font-medium border border-rose-800/50'
                : 'text-rose-400/80 hover:text-rose-300'
            }`}
          >
            <ShieldAlert className="w-3 h-3" />
            Attacks (3)
          </button>
          <button
            onClick={() => setActiveTab('benign')}
            className={`px-2.5 py-1 rounded transition-colors flex items-center gap-1 ${
              activeTab === 'benign'
                ? 'bg-emerald-950/80 text-emerald-300 font-medium border border-emerald-800/50'
                : 'text-emerald-400/80 hover:text-emerald-300'
            }`}
          >
            <CheckCircle className="w-3 h-3" />
            Benign (6)
          </button>
        </div>
      </div>

      {/* Scenario Pill Grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 md:grid-cols-3 gap-2 mb-4">
        {filteredScenarios.map((scenario) => {
          const isSelected = selectedScenarioId === scenario.scenario_id;
          const isAttack =
            scenario.category === 'PHISHING' || scenario.category === 'PROMPT_INJECTION';

          return (
            <button
              key={scenario.scenario_id}
              onClick={() => setSelectedScenarioId(scenario.scenario_id)}
              className={`flex items-start gap-2.5 p-2.5 rounded border text-left transition-all relative cursor-pointer ${
                isSelected
                  ? isAttack
                    ? 'bg-rose-950/50 border-rose-500 shadow-[0_0_12px_rgba(244,63,94,0.2)]'
                    : 'bg-cyan-950/50 border-cyan-500 shadow-[0_0_12px_rgba(6,182,212,0.2)]'
                  : 'bg-slate-900/40 border-slate-800/80 hover:border-slate-700 hover:bg-slate-900/80'
              }`}
            >
              <div className="mt-0.5">{getScenarioIcon(scenario)}</div>
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-1">
                  <span className="text-xs font-semibold text-slate-200 truncate">
                    {scenario.title}
                  </span>
                  <span
                    className={`text-[9px] font-mono px-1.5 py-0.2 rounded font-semibold ${
                      isAttack
                        ? 'bg-rose-950 text-rose-400 border border-rose-800/60'
                        : 'bg-slate-800 text-slate-300'
                    }`}
                  >
                    {scenario.expected_risk}
                  </span>
                </div>
                <p className="text-[10px] text-slate-400 line-clamp-1 mt-0.5">
                  {scenario.description}
                </p>
              </div>
            </button>
          );
        })}
      </div>

      {/* Execution Controls Bar */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pt-3 border-t border-slate-800/80 bg-slate-950/40 p-3 rounded">
        {/* Scenario Summary Info */}
        <div className="text-xs">
          <span className="text-slate-400">Target Scenario: </span>
          <span className="font-semibold text-white font-mono">
            {currentScenario?.title || 'None Selected'}
          </span>
          {currentScenario?.attack_type && (
            <span className="ml-2 text-[10px] font-mono px-1.5 py-0.5 rounded bg-rose-950 text-rose-300 border border-rose-800/60">
              {currentScenario.attack_type}
            </span>
          )}
        </div>

        {/* Pipeline Toggle Checkboxes & Launch CTA */}
        <div className="flex flex-wrap items-center gap-4">
          <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer font-mono">
            <input
              type="checkbox"
              checked={runLlm}
              onChange={(e) => setRunLlm(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0"
            />
            <span>Phase 2B LLM Advisory</span>
          </label>

          <label className="flex items-center gap-1.5 text-xs text-slate-300 cursor-pointer font-mono">
            <input
              type="checkbox"
              checked={proposeActions}
              onChange={(e) => setProposeActions(e.target.checked)}
              className="rounded bg-slate-900 border-slate-700 text-cyan-500 focus:ring-0 focus:ring-offset-0"
            />
            <span>Phase 3 Policy Gating</span>
          </label>

          <button
            onClick={handleLaunch}
            disabled={isTriggering || !selectedScenarioId}
            className="flex items-center gap-2 px-4 py-2 rounded bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white font-semibold text-xs font-mono shadow-[0_0_15px_rgba(6,182,212,0.3)] transition-all disabled:opacity-50 disabled:cursor-not-allowed cursor-pointer"
          >
            <Play className={`w-3.5 h-3.5 fill-current ${isTriggering ? 'animate-pulse' : ''}`} />
            <span>{isTriggering ? 'Executing Sandbox Quarantine...' : 'Trigger Quarantine Pipeline'}</span>
          </button>
        </div>
      </div>
    </div>
  );
};
