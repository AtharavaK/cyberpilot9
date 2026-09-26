import React from 'react';
import { Bot, Shield, Code, Globe, Server, FileText, Search, AlertTriangle, CheckCircle2, Settings, Loader2 } from 'lucide-react';

const AGENTS = [
  {
    key: 'master',
    name: 'Master Agent',
    icon: Bot,
    responsibility: 'Workflow coordination',
    focus: 'Assessment planning, agent orchestration, state management',
    tools: 'LangGraph, LangChain',
    statusKey: 'INITIALIZING',
  },
  {
    key: 'recon',
    name: 'Recon Agent',
    icon: Search,
    responsibility: 'Collect authorized target information',
    focus: 'APIs, Auth methods, Public endpoints, AI models',
    tools: 'Nmap',
    statusKey: 'RECONNAISSANCE',
  },
  {
    key: 'ai-security',
    name: 'AI Security Agent',
    icon: Shield,
    responsibility: 'AI-specific vulnerability assessment',
    focus: 'Prompt injection, Jailbreak, Data exposure, Model DoS',
    tools: 'Custom LLM test harness',
    statusKey: 'SECURITY_ANALYSIS',
  },
  {
    key: 'api-security',
    name: 'API Security Agent',
    icon: Globe,
    responsibility: 'API security assessment',
    focus: 'Auth, Rate limiting, CORS, Input validation',
    tools: 'OWASP ZAP',
    statusKey: 'SECURITY_ANALYSIS',
  },
  {
    key: 'code-review',
    name: 'Code Review Agent',
    icon: Code,
    responsibility: 'Source code security review',
    focus: 'Hardcoded secrets, Dependency flaws, Insecure patterns',
    tools: 'Semgrep, Bandit, Gitleaks',
    statusKey: 'SECURITY_ANALYSIS',
  },
  {
    key: 'infrastructure',
    name: 'Infrastructure Agent',
    icon: Server,
    responsibility: 'Deployment security analysis',
    focus: 'Docker config, TLS, DB config, Cloud permissions',
    tools: 'Trivy, tfsec',
    statusKey: 'SECURITY_ANALYSIS',
  },
  {
    key: 'risk-analysis',
    name: 'Risk Analysis Agent',
    icon: AlertTriangle,
    responsibility: 'Severity calculation & prioritization',
    focus: 'Risk score, Severity level, Business impact',
    tools: 'CVSS, Custom weighting',
    statusKey: 'RISK_SCORING',
  },
  {
    key: 'compliance',
    name: 'Compliance Agent',
    icon: FileText,
    responsibility: 'Standards mapping & compliance',
    focus: 'OWASP LLM Top 10, NIST CSF, ISO 27001',
    tools: 'Policy-as-code rules',
    statusKey: 'RISK_SCORING',
  },
  {
    key: 'recommendation',
    name: 'Recommendation Agent',
    icon: Settings,
    responsibility: 'Remediation guidance generation',
    focus: 'Secure coding, Best practices, Quick fixes',
    tools: 'Remediation templates',
    statusKey: 'RECOMMENDATIONS',
  },
  {
    key: 'report',
    name: 'Report Agent',
    icon: CheckCircle2,
    responsibility: 'Structured report creation',
    focus: 'Executive summary, Technical report, PDF export',
    tools: 'WeasyPrint, Jinja2 templates',
    statusKey: 'COMPLETED',
  },
];

const STAGE_ORDER = [
  'INITIALIZING',
  'RECONNAISSANCE',
  'SECURITY_ANALYSIS',
  'RISK_SCORING',
  'COMPLIANCE_MAPPING',
  'RECOMMENDATIONS',
  'COMPLETED',
];

function getStageIndex(status) {
  return STAGE_ORDER.indexOf(status);
}

function getAgentStatus(agentStatusKey, currentScanStatus) {
  if (!currentScanStatus) return 'pending';
  const agentIdx = STAGE_ORDER.indexOf(agentStatusKey);
  const currentIdx = getStageIndex(currentScanStatus);
  
  if (currentScanStatus === 'COMPLETED') return 'done';
  
  // Master Agent (INITIALIZING) orchestrates the entire workflow
  if (agentStatusKey === 'INITIALIZING') {
    return currentScanStatus !== 'COMPLETED' ? 'active' : 'done';
  }
  
  if (agentIdx < currentIdx) return 'done';
  if (agentIdx === currentIdx) return 'active';
  return 'pending';
}

export default function AgentsPanel({ currentScanStatus }) {
  return (
    <div className="animate-fade-in">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <Bot size={24} color="var(--accent-primary)" />
        <h2 className="heading-2" style={{ margin: 0 }}>AI Agent Pipeline</h2>
        <span className="badge warning" style={{ marginLeft: 'auto' }}>
          {currentScanStatus ? `${currentScanStatus}` : 'Idle'}
        </span>
      </div>

      <p className="text-muted" style={{ marginBottom: '1.5rem' }}>
        CyberPilot orchestrates 10 specialized AI agents through a LangGraph workflow. 
        Each agent has a distinct responsibility and simulated toolset.
      </p>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {AGENTS.map((agent) => {
          const status = getAgentStatus(agent.statusKey, currentScanStatus);
          const Icon = agent.icon;
          
          return (
            <div
              key={agent.key}
              style={{
                display: 'flex',
                gap: '1rem',
                padding: '1.25rem',
                borderRadius: '12px',
                background: status === 'active'
                  ? 'rgba(0,240,255,0.06)'
                  : status === 'done'
                  ? 'rgba(16,185,129,0.05)'
                  : 'rgba(255,255,255,0.01)',
                border: `1px solid ${
                  status === 'active'
                    ? 'rgba(0,240,255,0.2)'
                    : status === 'done'
                    ? 'rgba(16,185,129,0.2)'
                    : 'rgba(255,255,255,0.03)'
                }`,
                transition: 'all 0.3s ease',
              }}
            >
              <div
                style={{
                  width: '48px',
                  height: '48px',
                  borderRadius: '10px',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  background: status === 'active'
                    ? 'rgba(0,240,255,0.15)'
                    : status === 'done'
                    ? 'rgba(16,185,129,0.15)'
                    : 'rgba(255,255,255,0.05)',
                  flexShrink: 0,
                }}
              >
                {status === 'active' ? (
                  <Loader2 size={24} color="var(--accent-primary)" style={{ animation: 'spin 1s linear infinite' }} />
                ) : status === 'done' ? (
                  <CheckCircle2 size={24} color="var(--success)" />
                ) : (
                  <Icon size={24} color="var(--text-secondary)" opacity={0.6} />
                )}
              </div>

              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
                  <h3 style={{ fontSize: '1.05rem', fontWeight: 600, color: status === 'active' ? 'var(--accent-primary)' : status === 'done' ? 'var(--success)' : 'var(--text-primary)' }}>
                    {agent.name}
                  </h3>
                  <span className={`badge ${status === 'active' ? 'warning' : status === 'done' ? 'success' : ''}`}>
                    {status === 'active' ? 'Running' : status === 'done' ? 'Done' : 'Pending'}
                  </span>
                </div>
                <p className="text-muted" style={{ marginTop: '0.25rem', fontSize: '0.85rem' }}>
                  {agent.responsibility}
                </p>
                <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem', flexWrap: 'wrap', fontSize: '0.8rem' }}>
                  <span className="text-muted"><strong>Focus:</strong> {agent.focus}</span>
                  <span className="text-muted"><strong>Tools:</strong> {agent.tools}</span>
                </div>
              </div>
            </div>
          );
        })}
      </div>

      {/* Legend */}
      <div className="glass-card" style={{ marginTop: '2rem', padding: '1rem' }}>
        <h4 style={{ marginBottom: '0.75rem', fontSize: '0.9rem' }}>Workflow Stages</h4>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', fontSize: '0.8rem' }}>
          {STAGE_ORDER.map((stage, idx) => (
            <span key={stage} style={{ 
              display: 'flex', 
              alignItems: 'center', 
              gap: '0.35rem',
              color: currentScanStatus && getStageIndex(currentScanStatus) >= idx ? 'var(--success)' : 'var(--text-secondary)'
            }}>
              <span style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                background: currentScanStatus && getStageIndex(currentScanStatus) >= idx ? 'var(--success)' : 'rgba(255,255,255,0.2)',
              }} />
              {stage.replace('_', ' ')}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}