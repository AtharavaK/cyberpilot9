import React from 'react';
import { Bot, Shield, Code, Globe, Server, FileText, Settings, Search, AlertTriangle, CheckCircle2, Loader2 } from 'lucide-react';

const AGENTS = [
  { key: 'master', name: 'Master Security Agent', icon: Bot, role: 'Workflow coordination', tools: 'LangGraph, LangChain', statusKey: 'master' },
  { key: 'recon', name: 'Reconnaissance Agent', icon: Search, role: 'Network and service discovery', tools: 'Nmap', statusKey: 'RECONNAISSANCE' },
  { key: 'code', name: 'Code Security Agent', icon: Code, role: 'Source code security review', tools: 'Semgrep, Bandit, Gitleaks', statusKey: 'SECURITY_ANALYSIS' },
  { key: 'infra', name: 'Infrastructure Agent', icon: Server, role: 'Deployment and config security', tools: 'Trivy', statusKey: 'SECURITY_ANALYSIS' },
  { key: 'web', name: 'Web Security Agent', icon: Globe, role: 'Web application security', tools: 'OWASP ZAP', statusKey: 'SECURITY_ANALYSIS' },
  { key: 'api', name: 'API Security Agent', icon: Shield, role: 'API security assessment', tools: 'OWASP ZAP', statusKey: 'SECURITY_ANALYSIS' },
  { key: 'ai', name: 'AI Security Agent', icon: AlertTriangle, role: 'AI/ML vulnerability assessment', tools: 'Custom LLM test harness', statusKey: 'SECURITY_ANALYSIS' },
  { key: 'risk', name: 'Risk Analysis Agent', icon: AlertTriangle, role: 'Severity calculation and prioritization', tools: 'CVSS, Custom weighting', statusKey: 'RISK_SCORING' },
  { key: 'compliance', name: 'Compliance Agent', icon: FileText, role: 'Standards mapping', tools: 'Policy-as-code rules', statusKey: 'COMPLIANCE' },
  { key: 'report', name: 'Report Agent', icon: CheckCircle2, role: 'Structured report creation', tools: 'WeasyPrint, Jinja2', statusKey: 'COMPLETED' },
];

export default function AgentsPage() {
  return (
    <div>
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Bot size={24} color="var(--accent-primary)" />
          <h1 className="heading-1">Specialized Agents</h1>
        </div>
        <p className="text-muted">
          CyberPilot orchestrates specialized security agents through a LangGraph workflow.
          Each agent has a distinct responsibility and toolset.
        </p>
      </header>

      <div className="finding-list">
        {AGENTS.map((agent) => {
          const Icon = agent.icon;
          return (
            <div key={agent.key} className="glass-card" style={{ padding: '1.5rem', display: 'flex', gap: '1rem', alignItems: 'flex-start' }}>
              <div style={{
                width: '56px',
                height: '56px',
                borderRadius: '12px',
                background: 'rgba(0,240,255,0.1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                flexShrink: 0,
              }}>
                <Icon size={28} color="var(--accent-primary)" />
              </div>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap', marginBottom: '0.5rem' }}>
                  <h3 style={{ margin: 0, fontSize: '1.1rem', fontWeight: 600 }}>{agent.name}</h3>
                  <span className="badge info" style={{ fontSize: '0.7rem' }}>{agent.statusKey.replace('_', ' ')}</span>
                </div>
                <p className="text-muted" style={{ fontSize: '0.85rem', marginBottom: '0.5rem' }}>
                  {agent.role}
                </p>
                <div className="text-muted" style={{ fontSize: '0.8rem' }}>
                  <strong>Tools:</strong> {agent.tools}
                </div>
              </div>
            </div>
          );
        })}
      </div>

      <div className="glass-card" style={{ marginTop: '1.5rem', padding: '1.5rem' }}>
        <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.1rem' }}>Orchestration Architecture</h3>
        <div className="text-muted" style={{ fontSize: '0.85rem', lineHeight: 1.8 }}>
          <div>Authorized Target → Target Normalization (Phase 1) → Master Agent creates AssessmentPlan → SecurityPolicy validates each task → Tasks dispatched to specialized agents → Tools execute via ToolManager → Findings normalized → AI Analysis (optional) → Decisions recorded → Bounded iteration loop → Risk Scoring → Compliance → Recommendations → Report → END</div>
          <div style={{ marginTop: '0.5rem', fontSize: '0.8rem' }}>
            The Master Agent never executes shell commands directly. All tool execution goes
            through the ToolManager / scanner abstraction.</div>
        </div>
      </div>
    </div>
  );
}
