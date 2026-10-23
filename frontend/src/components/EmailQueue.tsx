import React, { useState } from 'react';
import {
  Inbox,
  Lock,
  CheckCircle2,
  XCircle,
  AlertOctagon,
  Shield,
  Search,
} from 'lucide-react';
import type { EmailListItem } from '../types';

interface EmailQueueProps {
  emails: EmailListItem[];
  selectedEmailId: string | null;
  onSelectEmail: (emailId: string) => void;
  isLoading: boolean;
}

export const EmailQueue: React.FC<EmailQueueProps> = ({
  emails,
  selectedEmailId,
  onSelectEmail,
  isLoading,
}) => {
  const [filter, setFilter] = useState<string>('all');
  const [searchQuery, setSearchQuery] = useState<string>('');

  const filteredEmails = emails.filter((email) => {
    // Search query matching
    const matchesSearch =
      searchQuery === '' ||
      email.subject.toLowerCase().includes(searchQuery.toLowerCase()) ||
      email.sender.toLowerCase().includes(searchQuery.toLowerCase()) ||
      (email.threat_category && email.threat_category.toLowerCase().includes(searchQuery.toLowerCase()));

    if (!matchesSearch) return false;

    // Filter matching
    if (filter === 'pending') return email.pending_approval_count > 0;
    if (filter === 'quarantined') return email.is_quarantined || email.primary_action_type === 'QUARANTINE_EMAIL';
    if (filter === 'executed') return email.primary_action_state === 'EXECUTED';
    if (filter === 'rejected') return email.primary_action_state === 'REJECTED';
    if (filter === 'attacks')
      return (
        email.static_risk_label === 'CRITICAL' ||
        email.threat_category === 'PHISHING' ||
        email.threat_category === 'PROMPT_INJECTION'
      );
    return true;
  });

  const getRiskBadge = (label: string) => {
    switch (label) {
      case 'CRITICAL':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-950/80 text-rose-300 border border-rose-700/80 flex items-center gap-1 animate-pulse">
            <span className="w-1.5 h-1.5 rounded-full bg-rose-500" />
            CRITICAL
          </span>
        );
      case 'SUSPICIOUS':
      case 'HIGH':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-amber-950/80 text-amber-300 border border-amber-700/80">
            HIGH RISK
          </span>
        );
      case 'MEDIUM':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-yellow-950/80 text-yellow-300 border border-yellow-700/80">
            MEDIUM
          </span>
        );
      case 'LOW':
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-cyan-950/80 text-cyan-300 border border-cyan-800/80">
            LOW
          </span>
        );
      default:
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-800/80">
            SAFE
          </span>
        );
    }
  };

  const getActionStatePill = (state?: string | null) => {
    if (!state) return null;
    switch (state) {
      case 'PENDING_APPROVAL':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold bg-yellow-950/80 text-yellow-300 border border-yellow-600/70">
            <Lock className="w-3 h-3 text-yellow-400" />
            PENDING APPROVAL
          </span>
        );
      case 'APPROVED':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-blue-950/80 text-blue-300 border border-blue-600/70">
            <CheckCircle2 className="w-3 h-3 text-blue-400" />
            APPROVED
          </span>
        );
      case 'EXECUTED':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-emerald-950/80 text-emerald-300 border border-emerald-600/70">
            <CheckCircle2 className="w-3 h-3 text-emerald-400" />
            EXECUTED (SIM)
          </span>
        );
      case 'REJECTED':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-slate-900 text-slate-400 border border-slate-700">
            <XCircle className="w-3 h-3 text-slate-400" />
            REJECTED
          </span>
        );
      case 'FAILED':
        return (
          <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950/80 text-rose-300 border border-rose-700">
            <AlertOctagon className="w-3 h-3 text-rose-400" />
            FAILED
          </span>
        );
      default:
        return (
          <span className="px-1.5 py-0.5 rounded text-[10px] font-mono bg-slate-800 text-slate-300">
            {state}
          </span>
        );
    }
  };

  return (
    <div className="bg-[#0b101b] border border-slate-800 rounded-lg flex flex-col h-[740px]">
      {/* Header & Filter Controls */}
      <div className="p-3 border-b border-slate-800">
        <div className="flex items-center justify-between gap-2 mb-2">
          <div className="flex items-center gap-2">
            <Inbox className="w-4 h-4 text-cyan-400" />
            <h2 className="text-xs font-bold uppercase tracking-wider text-white font-mono">
              Email Threat Queue
            </h2>
            <span className="px-1.5 py-0.2 rounded text-[10px] font-mono bg-slate-800 text-cyan-400 font-semibold">
              {emails.length} Total
            </span>
          </div>

          {/* Search Box */}
          <div className="relative w-44">
            <Search className="w-3.5 h-3.5 text-slate-500 absolute left-2 top-2" />
            <input
              type="text"
              placeholder="Filter queue..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-full pl-7 pr-2 py-1 text-xs bg-slate-900 border border-slate-800 rounded text-slate-200 placeholder-slate-500 focus:outline-none focus:border-cyan-500 font-mono"
            />
          </div>
        </div>

        {/* Filter Badges */}
        <div className="flex items-center gap-1 overflow-x-auto text-[11px] font-mono scrollbar-none pt-1">
          <button
            onClick={() => setFilter('all')}
            className={`px-2 py-0.5 rounded transition-colors cursor-pointer ${
              filter === 'all'
                ? 'bg-slate-700 text-white font-semibold'
                : 'bg-slate-900/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            All
          </button>
          <button
            onClick={() => setFilter('pending')}
            className={`px-2 py-0.5 rounded transition-colors flex items-center gap-1 cursor-pointer ${
              filter === 'pending'
                ? 'bg-yellow-950 text-yellow-300 font-semibold border border-yellow-700'
                : 'bg-slate-900/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            <Lock className="w-3 h-3 text-yellow-400" />
            Pending Action
          </button>
          <button
            onClick={() => setFilter('attacks')}
            className={`px-2 py-0.5 rounded transition-colors flex items-center gap-1 cursor-pointer ${
              filter === 'attacks'
                ? 'bg-rose-950 text-rose-300 font-semibold border border-rose-700'
                : 'bg-slate-900/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            Attacks
          </button>
          <button
            onClick={() => setFilter('quarantined')}
            className={`px-2 py-0.5 rounded transition-colors flex items-center gap-1 cursor-pointer ${
              filter === 'quarantined'
                ? 'bg-purple-950 text-purple-300 font-semibold border border-purple-700'
                : 'bg-slate-900/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            Quarantined
          </button>
          <button
            onClick={() => setFilter('executed')}
            className={`px-2 py-0.5 rounded transition-colors flex items-center gap-1 cursor-pointer ${
              filter === 'executed'
                ? 'bg-emerald-950 text-emerald-300 font-semibold border border-emerald-700'
                : 'bg-slate-900/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            Executed
          </button>
        </div>
      </div>

      {/* Queue List Container */}
      <div className="flex-1 overflow-y-auto divide-y divide-slate-800/60 p-1">
        {isLoading && emails.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-500 text-xs font-mono">
            <span className="animate-spin mb-2 text-cyan-400">⚙️</span>
            Loading email queue...
          </div>
        ) : filteredEmails.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-48 text-slate-500 text-xs font-mono p-4 text-center">
            <Shield className="w-8 h-8 text-slate-600 mb-2" />
            <p className="font-semibold text-slate-400">No emails matching filter</p>
            <p className="text-[11px] text-slate-600 mt-1">
              Trigger a scenario from the simulator above to evaluate an email.
            </p>
          </div>
        ) : (
          filteredEmails.map((email) => {
            const isSelected = selectedEmailId === email.id;
            return (
              <div
                key={email.id}
                onClick={() => onSelectEmail(email.id)}
                className={`p-3 cursor-pointer transition-all rounded text-left ${
                  isSelected
                    ? 'bg-cyan-950/40 border border-cyan-500/60 shadow-[0_0_12px_rgba(6,182,212,0.15)]'
                    : 'hover:bg-slate-900/60 border border-transparent'
                }`}
              >
                {/* Top Row: Sender & Timestamp */}
                <div className="flex items-center justify-between gap-2 mb-1">
                  <span className="text-xs font-mono font-semibold text-slate-300 truncate">
                    {email.sender || 'Unknown Sender'}
                  </span>
                  <span className="text-[10px] font-mono text-slate-500 whitespace-nowrap">
                    {email.date_str || email.created_at.slice(11, 19)}
                  </span>
                </div>

                {/* Subject */}
                <h3 className="text-xs font-medium text-white mb-2 line-clamp-1">
                  {email.subject || '(No Subject)'}
                </h3>

                {/* Threat Indicators Row */}
                <div className="flex flex-wrap items-center gap-1.5 mb-2">
                  {getRiskBadge(email.static_risk_label)}

                  {email.threat_category && email.threat_category !== 'BENIGN' && (
                    <span className="px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-rose-950/60 text-rose-300 border border-rose-800/60">
                      {email.threat_category}
                    </span>
                  )}

                  {email.urgency && (
                    <span
                      className={`px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold ${
                        email.urgency >= 4
                          ? 'bg-rose-950 text-rose-300 border border-rose-800'
                          : email.urgency === 3
                          ? 'bg-amber-950 text-amber-300 border border-amber-800'
                          : 'bg-slate-800 text-slate-400'
                      }`}
                    >
                      Urgency {email.urgency}/5
                    </span>
                  )}

                  {email.confidence && (
                    <span className="text-[10px] font-mono text-slate-500">
                      {Math.round(email.confidence * 100)}% conf
                    </span>
                  )}
                </div>

                {/* Proposed Action & Approval State */}
                <div className="flex items-center justify-between gap-2 pt-1.5 border-t border-slate-800/40 text-[10px] font-mono">
                  <div className="text-slate-400 truncate">
                    {email.primary_action_type ? (
                      <span className="text-slate-300 font-semibold">
                        Proposal: {email.primary_action_type.replace(/_/g, ' ')}
                      </span>
                    ) : (
                      <span className="text-slate-500">No actions required</span>
                    )}
                  </div>
                  <div>{getActionStatePill(email.primary_action_state)}</div>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
};
