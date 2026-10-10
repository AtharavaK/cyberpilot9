import React, { useEffect, useState } from 'react';
import { Wrench, Download, RefreshCw, AlertCircle, ExternalLink } from 'lucide-react';
import { getToolsStatus, getAiStatus } from '../services/api.js';
import { ErrorBanner, LoadingSkeleton, StatusIndicator } from '../components/ui.jsx';

const TOOL_DESCRIPTIONS = {
  Nmap: 'Network mapper — port discovery, OS detection, service fingerprinting',
  Semgrep: 'Static analysis — finds security issues in source code',
  Bandit: 'Python static analysis — security linting for Python code',
  Gitleaks: 'Secret detection — finds exposed credentials in source code',
  Trivy: 'Vulnerability scanner — container images, filesystems, config',
  'OWASP ZAP': 'Web application security scanner — XSS, SQLi, auth, API',
  'AI Security Tester': 'AI/ML security testing — prompt injection, data exposure',
  'AI Engine (Ollama)': 'Large language model backend for AI security analysis',
};

export default function ToolsPage() {
  const [tools, setTools] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);

  const loadStatus = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getToolsStatus();
      // Also get AI status
      const aiStatus = await getAiStatus();
      // Replace the AI engine entry with actual from AI status
      const withAi = { ...data, tools: data.tools.map(t => {
        if (t.name === 'AI Engine (Ollama)') {
          return {
            ...t,
            installed: true,
            available: aiStatus.ai_ready,
            status: aiStatus.ai_ready ? 'ready' : 'unavailable',
            version: aiStatus.model,
            description: TOOL_DESCRIPTIONS['AI Engine (Ollama)'],
          };
        }
        return t;
      })};
      setTools(withAi);
    } catch (err) {
      setError(err.message || 'Failed to load tool status');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadStatus();
  }, []);

  return (
    <div>
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Wrench size={24} color="var(--accent-primary)" />
          <h1 className="heading-1">Tools</h1>
        </div>
        <p className="text-muted">Status of all security tools integrated with CyberPilot.</p>
      </header>

      {error && <ErrorBanner error={error} onRetry={loadStatus} />}

      {loading ? (
        <LoadingSkeleton lines={10} height="60px" />
      ) : tools ? (
        <div className="glass-card" style={{ padding: '1.5rem' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
            <h2 className="heading-2" style={{ margin: 0 }}>Tool Status</h2>
            <button className="btn btn-outline" style={{ padding: '0.3rem 0.7rem', fontSize: '0.8rem' }} onClick={loadStatus}>
              <RefreshCw size={14} /> Refresh
            </button>
          </div>
          <table className="table">
            <thead>
              <tr>
                <th>Tool</th>
                <th>Status</th>
                <th>Version</th>
                <th>Enabled</th>
                <th>Description</th>
              </tr>
            </thead>
            <tbody>
              {tools.tools.map((t) => (
                <tr key={t.name}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <Wrench size={16} color="var(--text-secondary)" />
                      <span style={{ fontWeight: 500 }}>{t.name}</span>
                    </div>
                  </td>
                  <td>
                    <StatusIndicator status={
                      t.available ? 'ready' : (t.installed ? 'unavailable' : 'not_installed')
                    } />
                  </td>
                  <td className="text-muted" style={{ fontSize: '0.85rem' }}>
                    {t.version || '—'}
                  </td>
                  <td>
                    <span className={`badge ${t.enabled ? 'success' : 'warning'}`} style={{ fontSize: '0.75rem' }}>
                      {t.enabled ? 'Yes' : 'No'}
                    </span>
                  </td>
                  <td className="text-muted" style={{ fontSize: '0.85rem' }}>
                    {t.description || TOOL_DESCRIPTIONS[t.name] || ''}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {tools.tools.some(t => !t.installed) && (
            <div style={{ marginTop: '1.5rem', padding: '1rem', background: 'rgba(245,158,11,0.08)', border: '1px solid rgba(245,158,11,0.3)', borderRadius: '8px' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <AlertCircle size={20} color="var(--warning)" />
                <strong style={{ color: 'var(--warning)' }}>Some tools are not installed</strong>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Install the missing tools and restart the backend to enable them.
                Unavailable tools will not appear as successful in scan results.
              </p>
            </div>
          )}
        </div>
      ) : null}

      {/* Install Guide */}
      <div className="glass-card" style={{ marginTop: '1.5rem', padding: '1.5rem' }}>
        <h2 className="heading-2" style={{ margin: '0 0 1rem 0' }}>Installation Guide</h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {[
            { name: 'Nmap', install: 'sudo apt install nmap' },
            { name: 'Semgrep', install: 'pip install semgrep' },
            { name: 'Bandit', install: 'pip install bandit' },
            { name: 'Gitleaks', install: 'brew install gitleaks' },
            { name: 'Trivy', install: 'brew install aquasecurity/trivy/trivy' },
            { name: 'OWASP ZAP', install: 'See https://www.zaproxy.org/download/' },
            { name: 'Ollama', install: 'curl -fsSL https://ollama.com/install.sh | sh' },
          ].map((t) => {
            const toolInfo = tools?.tools?.find(tl => tl.name === t.name);
            const installed = toolInfo?.installed ?? false;
            return (
              <div key={t.name} style={{
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                padding: '0.5rem 0',
                borderBottom: '1px solid var(--border-color)',
              }}>
                <div>
                  <span style={{ fontWeight: 500 }}>{t.name}</span>
                  <div className="text-muted" style={{ fontSize: '0.8rem', marginTop: '0.1rem' }}>
                    {t.install}
                  </div>
                </div>
                <span className={`badge ${installed ? 'success' : 'warning'}`} style={{ fontSize: '0.75rem' }}>
                  {installed ? 'Installed' : 'Not Installed'}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
