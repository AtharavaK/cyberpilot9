import React from 'react';
import { Terminal, Loader2, CheckCircle2, Clock } from 'lucide-react';

const STAGES = [
  { key: 'INITIALIZING', label: 'Master Agent' },
  { key: 'RECONNAISSANCE', label: 'Recon Agent' },
  { key: 'SECURITY_ANALYSIS', label: 'Security Agents' },
  { key: 'RISK_SCORING', label: 'Risk Analysis Agent' },
  { key: 'COMPLIANCE_MAPPING', label: 'Compliance Agent' },
  { key: 'RECOMMENDATIONS', label: 'Recommendation Agent' },
  { key: 'COMPLETED', label: 'Report Agent' },
];

function getStageIndex(status) {
  const idx = STAGES.findIndex((s) => s.key === status);
  return idx === -1 ? -1 : idx;
}

export default function AgentProgress({ status }) {
  const currentIdx = getStageIndex(status);

  return (
    <div className="glass-card animate-fade-in" style={{ marginBottom: '2rem' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <Terminal size={22} color="var(--accent-primary)" />
        <h2 className="heading-2" style={{ margin: 0 }}>Agent Pipeline</h2>
        <span className="badge warning" style={{ marginLeft: 'auto' }}>
          {status === 'COMPLETED' ? 'Complete' : 'Running…'}
        </span>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
        {STAGES.map((stage, idx) => {
          // Master Agent (INITIALIZING) is active throughout entire workflow
          const isMasterAgent = stage.key === 'INITIALIZING';
          const masterActive = isMasterAgent && status !== 'COMPLETED';
          
          const done = idx < currentIdx || status === 'COMPLETED';
          const active = (idx === currentIdx && status !== 'COMPLETED') || masterActive;
          const pending = idx > currentIdx && status !== 'COMPLETED' && !masterActive;

          return (
            <div
              key={stage.key}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '1rem',
                padding: '0.75rem 1rem',
                borderRadius: '8px',
                background: active
                  ? 'rgba(0,240,255,0.06)'
                  : done
                  ? 'rgba(16,185,129,0.05)'
                  : 'rgba(255,255,255,0.01)',
                border: `1px solid ${
                  active
                    ? 'rgba(0,240,255,0.2)'
                    : done
                    ? 'rgba(16,185,129,0.2)'
                    : 'rgba(255,255,255,0.03)'
                }`,
                transition: 'all 0.3s ease',
              }}
            >
              {done ? (
                <CheckCircle2 size={20} color="var(--success)" />
              ) : active ? (
                <Loader2
                  size={20}
                  color="var(--accent-primary)"
                  style={{ animation: 'spin 1s linear infinite' }}
                />
              ) : (
                <Clock size={20} color="var(--text-secondary)" opacity={0.5} />
              )}
              <span
                style={{
                  fontWeight: active ? 600 : 500,
                  color: active
                    ? 'var(--accent-primary)'
                    : done
                    ? 'var(--success)'
                    : 'var(--text-secondary)',
                  fontSize: '0.95rem',
                }}
              >
                {stage.label}
              </span>
              {active && (
                <span
                  className="text-muted"
                  style={{ marginLeft: 'auto', fontSize: '0.8rem', animation: 'fadeIn 0.5s ease' }}
                >
                  In progress…
                </span>
              )}
              {done && (
                <span
                  className="text-muted"
                  style={{ marginLeft: 'auto', fontSize: '0.8rem', color: 'var(--success)' }}
                >
                  Done
                </span>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
}
