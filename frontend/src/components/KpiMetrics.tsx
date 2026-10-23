import React from 'react';
import {
  Mail,
  ShieldAlert,
  Clock,
  CheckCircle,
  AlertOctagon,
  ShieldCheck,
} from 'lucide-react';
import type { EmailListItem } from '../types';

interface KpiMetricsProps {
  emails: EmailListItem[];
  isLoading: boolean;
}

export const KpiMetrics: React.FC<KpiMetricsProps> = ({ emails, isLoading }) => {
  // Derive actual metrics from existing loaded data
  const totalEmails = emails.length;
  const threatsDetected = emails.filter(
    (e) =>
      e.static_risk_label === 'CRITICAL' ||
      e.static_risk_label === 'SUSPICIOUS' ||
      e.threat_category === 'PHISHING' ||
      e.threat_category === 'PROMPT_INJECTION' ||
      e.threat_category === 'MALWARE' ||
      e.threat_category === 'SCAM'
  ).length;

  const pendingApprovals = emails.reduce((acc, curr) => acc + (curr.pending_approval_count || 0), 0);
  
  const executedActions = emails.filter((e) => e.primary_action_state === 'EXECUTED').length;

  const criticalThreats = emails.filter(
    (e) => e.static_risk_label === 'CRITICAL' || e.threat_level === 'CRITICAL'
  ).length;

  const quarantinedItems = emails.filter(
    (e) => e.is_quarantined || e.primary_action_type === 'QUARANTINE_EMAIL'
  ).length;

  const cards = [
    {
      title: 'Emails Analyzed',
      value: totalEmails,
      icon: Mail,
      color: 'text-cyan-400',
      bgColor: 'bg-cyan-950/30',
      borderColor: 'border-cyan-800/40',
      subtitle: 'Static + LLM pipeline',
    },
    {
      title: 'Threats Detected',
      value: threatsDetected,
      icon: ShieldAlert,
      color: 'text-amber-400',
      bgColor: 'bg-amber-950/30',
      borderColor: 'border-amber-800/40',
      subtitle: 'Phishing & injections',
    },
    {
      title: 'Pending Approvals',
      value: pendingApprovals,
      icon: Clock,
      color: 'text-yellow-400',
      bgColor: 'bg-yellow-950/30',
      borderColor: 'border-yellow-800/40',
      subtitle: 'Execution strictly locked',
      highlight: pendingApprovals > 0,
    },
    {
      title: 'Simulated Executions',
      value: executedActions,
      icon: CheckCircle,
      color: 'text-emerald-400',
      bgColor: 'bg-emerald-950/30',
      borderColor: 'border-emerald-800/40',
      subtitle: 'Post-approval drivers',
    },
    {
      title: 'Critical Threat Level',
      value: criticalThreats,
      icon: AlertOctagon,
      color: 'text-rose-400',
      bgColor: 'bg-rose-950/30',
      borderColor: 'border-rose-800/40',
      subtitle: 'High containment risk',
    },
    {
      title: 'Quarantined Items',
      value: quarantinedItems,
      icon: ShieldCheck,
      color: 'text-purple-400',
      bgColor: 'bg-purple-950/30',
      borderColor: 'border-purple-800/40',
      subtitle: 'Isolated from inbox',
    },
  ];

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {cards.map((card, idx) => {
        const Icon = card.icon;
        return (
          <div
            key={idx}
            className={`p-3 rounded-lg border ${card.borderColor} ${card.bgColor} relative overflow-hidden backdrop-blur-sm transition-all`}
          >
            {card.highlight && (
              <div className="absolute top-1.5 right-1.5 w-2 h-2 rounded-full bg-yellow-400 animate-ping" />
            )}
            <div className="flex items-center justify-between mb-1.5">
              <span className="text-[11px] font-medium text-slate-400 uppercase tracking-wider">
                {card.title}
              </span>
              <Icon className={`w-4 h-4 ${card.color}`} />
            </div>
            <div className="flex items-baseline gap-1.5">
              <span className="text-2xl font-bold font-mono text-white tracking-tight">
                {isLoading ? '...' : card.value}
              </span>
            </div>
            <p className="text-[10px] text-slate-400 font-mono mt-1 truncate">
              {card.subtitle}
            </p>
          </div>
        );
      })}
    </div>
  );
};
