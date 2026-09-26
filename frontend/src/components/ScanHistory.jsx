import React, { useEffect, useState } from 'react';
import { FileText, Globe, ShieldAlert, Clock, CheckCircle2, Loader2, AlertCircle, Key, ArrowRight } from 'lucide-react';
import { listAllScans } from '../services/api.js';

const SEVERITY_COLOR = { HIGH: 'var(--error)', MEDIUM: 'var(--warning)', LOW: 'var(--success)' };
const STATUS_BADGE = {
  COMPLETED: { cls: 'success', label: 'Completed', icon: <CheckCircle2 size={12} /> },
  RUNNING: { cls: 'warning', label: 'Running', icon: <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> },
  RECONNAISSANCE: { cls: 'warning', label: 'Reconnaissance', icon: <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> },
  SECURITY_ANALYSIS: { cls: 'warning', label: 'Analyzing', icon: <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> },
  RISK_SCORING: { cls: 'warning', label: 'Scoring Risk', icon: <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> },
  RECOMMENDATIONS: { cls: 'warning', label: 'Recommending', icon: <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> },
  INITIALIZING: { cls: 'warning', label: 'Initializing', icon: <Loader2 size={12} style={{ animation: 'spin 1s linear infinite' }} /> },
};

export default function ScanHistory() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [needsAuth, setNeedsAuth] = useState(false);

  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const data = await listAllScans();
        setScans(data);
        setNeedsAuth(false);
      } catch (err) {
        if (err.status === 401) {
          setNeedsAuth(true);
          setError('Authentication required. Please create an API key in Settings.');
        } else {
          setError(err.message);
        }
      } finally {
        setLoading(false);
      }
    };
    fetchHistory();
  }, []);

  if (loading) {
    return (
      <div className="glass-panel" style={{ padding: '4rem', textAlign: 'center' }}>
        <Loader2 size={40} color="var(--accent-primary)" style={{ animation: 'spin 1s linear infinite', margin: '0 auto 1rem' }} />
        <p className="text-muted">Loading scan history…</p>
      </div>
    );
  }

  if (needsAuth) {
    return (
      <div className="glass-panel animate-fade-in" style={{ padding: '3rem 2rem', textAlign: 'center', maxWidth: '500px', margin: '0 auto' }}>
        <div style={{ fontSize: '3rem', marginBottom: '1rem' }}>🔐</div>
        <h2 className="heading-2" style={{ marginBottom: '0.5rem' }}>Authentication Required</h2>
        <p className="text-muted" style={{ marginBottom: '1.5rem', lineHeight: 1.6 }}>
          You need an API key to access scan history. 
          Create one in the <strong>Settings</strong> tab.
        </p>
        <button 
          onClick={() => window.location.hash = 'settings'}
          className="btn btn-primary"
          style={{ display: 'inline-flex', alignItems: 'center', gap: '0.5rem', margin: '0 auto' }}
        >
          <Key size={18} /> Go to Settings
          <ArrowRight size={18} />
        </button>
      </div>
    );
  }

  if (error) {
    return (
      <div className="glass-card" style={{ borderLeft: '4px solid var(--error)', color: 'var(--error)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <AlertCircle size={20} />
          <strong>Error:</strong> {error}
        </div>
      </div>
    );
  }

  return (
    <div className="animate-fade-in">
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.5rem' }}>
        <FileText size={24} color="var(--accent-primary)" />
        <h2 className="heading-2" style={{ margin: 0 }}>Scan History</h2>
        <span className="badge success" style={{ marginLeft: 'auto' }}>{scans.length} Records</span>
      </div>

      {scans.length === 0 ? (
        <div className="glass-panel" style={{ padding: '4rem 2rem', textAlign: 'center' }}>
          <FileText size={48} color="var(--text-secondary)" style={{ margin: '0 auto 1rem', opacity: 0.3 }} />
          <h3 style={{ color: 'var(--text-secondary)', fontWeight: 500 }}>No scans yet</h3>
          <p className="text-muted">Run your first assessment from the Dashboard tab.</p>
        </div>
      ) : (
        <div className="finding-list">
          {scans.map((scan) => {
            const badge = STATUS_BADGE[scan.status] || { cls: 'warning', label: scan.status, icon: null };
            const scoreColor =
              scan.overall_score >= 80 ? 'var(--success)'
              : scan.overall_score >= 60 ? 'var(--warning)'
              : 'var(--error)';

            return (
              <div key={scan.scan_id} className="glass-card" style={{ display: 'flex', flexWrap: 'wrap', gap: '1rem', alignItems: 'center' }}>
                {/* Icon */}
                <ShieldAlert size={32} color={scan.status === 'COMPLETED' ? scoreColor : 'var(--text-secondary)'} style={{ flexShrink: 0 }} />

                {/* Info */}
                <div style={{ flex: 1, minWidth: '200px' }}>
                  <div style={{ fontWeight: 600, color: 'var(--accent-primary)', wordBreak: 'break-all', fontSize: '0.95rem' }}>
                    <Globe size={14} style={{ marginRight: '0.4rem', verticalAlign: 'middle' }} />
                    {scan.target_url}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginTop: '0.3rem' }} className="text-muted">
                    <Clock size={13} />
                    <span style={{ fontSize: '0.8rem' }}>{scan.created_at}</span>
                    <span style={{ fontSize: '0.75rem', opacity: 0.6 }}>ID: {scan.scan_id.slice(0, 8)}…</span>
                  </div>
                </div>

                {/* Score */}
                {scan.status === 'COMPLETED' && (
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: '1.8rem', fontWeight: 700, color: scoreColor, lineHeight: 1 }}>
                      {scan.overall_score}
                    </div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-secondary)', marginTop: '2px' }}>/100</div>
                  </div>
                )}

                {/* Status Badge */}
                <span className={`badge ${badge.cls}`} style={{ display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  {badge.icon} {badge.label}
                </span>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
