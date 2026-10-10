import React, { useEffect, useState } from 'react';
import {
  Activity, FileText, AlertTriangle, CheckCircle2, Clock, Globe,
  Loader2, RefreshCw, ShieldAlert, Plus,
} from 'lucide-react';
import { Link } from 'react-router-dom';
import { getDashboardStats, getToolsStatus, getAiStatus } from '../services/api.js';
import { ErrorBanner, LoadingSkeleton, StatusIndicator, SeverityBadge } from '../components/ui.jsx';
import { useApp } from '../context/AppContext.jsx';
import { SEVERITY_CONFIG } from '../types/index.js';

const SEVERITY_CARDS = [
  { key: 'CRITICAL', label: 'Critical', icon: AlertTriangle, color: 'var(--error)' },
  { key: 'HIGH', label: 'High', icon: AlertTriangle, color: 'var(--error)' },
  { key: 'MEDIUM', label: 'Medium', icon: AlertTriangle, color: 'var(--warning)' },
  { key: 'LOW', label: 'Low', icon: AlertTriangle, color: 'var(--success)' },
];

export default function DashboardPage() {
  const [stats, setStats] = useState(null);
  const [tools, setTools] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const { checkBackend } = useApp();

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, toolsRes, aiRes] = await Promise.allSettled([
        getDashboardStats(),
        getToolsStatus(),
        getAiStatus(),
      ]);

      if (statsRes.status === 'fulfilled') setStats(statsRes.value);
      if (toolsRes.status === 'fulfilled') setTools(toolsRes.value);
      if (aiRes.status === 'fulfilled') setAiStatus(aiRes.value);

      if (statsRes.status === 'rejected') {
        setError(statsRes.reason?.message || 'Failed to load dashboard');
      }
    } catch (err) {
      setError(err.message || 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  const isLoading = loading && !stats;

  return (
    <div>
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.5rem' }}>
          <Activity size={24} color="var(--accent-primary)" />
          <h1 className="heading-1">Dashboard</h1>
          <button
            onClick={loadData}
            className="btn btn-outline"
            style={{ marginLeft: 'auto', padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
          >
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
        <p className="text-muted">
          Autonomous Multi-Agent AI Security Assessment Platform
        </p>
      </header>

      {error && <ErrorBanner error={error} onRetry={loadData} />}

      {isLoading ? (
        <>
          <div className="card-grid" style={{ marginBottom: '2rem' }}>
            <LoadingSkeleton lines={1} height="80px" />
            <LoadingSkeleton lines={1} height="80px" />
            <LoadingSkeleton lines={1} height="80px" />
            <LoadingSkeleton lines={1} height="80px" />
            <LoadingSkeleton lines={1} height="80px" />
            <LoadingSkeleton lines={1} height="80px" />
          </div>
          <LoadingSkeleton lines={5} />
        </>
      ) : (
        <>
          {/* Stats Cards */}
          {stats && (
            <div className="card-grid" style={{ marginBottom: '2rem' }}>
              <div className="stat-card">
                <div className="stat-label">Total Scans</div>
                <div className="stat-value" style={{ color: 'var(--accent-primary)' }}>
                  {stats.total_scans ?? 0}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Active Scans</div>
                <div className="stat-value" style={{ color: 'var(--warning)' }}>
                  {(stats.by_status?.RUNNING || stats.by_status?.RECONNAISSANCE ||
                    stats.by_status?.SECURITY_ANALYSIS || stats.by_status?.INITIALIZING || 0)}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Completed</div>
                <div className="stat-value" style={{ color: 'var(--success)' }}>
                  {stats.by_status?.COMPLETED || 0}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Findings (Open)</div>
                <div className="stat-value" style={{ color: 'var(--error)' }}>
                  {stats.findings_by_severity?.CRITICAL || stats.findings_by_severity?.HIGH || 0}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">Triage Needed</div>
                <div className="stat-value" style={{ color: 'var(--warning)' }}>
                  {stats.open_triage_count ?? 0}
                </div>
              </div>
              <div className="stat-card">
                <div className="stat-label">AI Status</div>
                <div style={{ marginTop: '0.5rem' }}>
                  {aiStatus ? (
                    <StatusIndicator status={aiStatus.ai_ready ? 'ready' : 'unavailable'} />
                  ) : (
                    <span className="text-muted">Unknown</span>
                  )}
                </div>
              </div>
            </div>
          )}

          {/* Severity Distribution */}
          {stats && stats.findings_by_severity && (
            <div className="glass-card" style={{ marginBottom: '2rem', padding: '1.5rem' }}>
              <h2 className="heading-2" style={{ margin: 0, marginBottom: '1rem' }}>
                Findings by Severity
              </h2>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {SEVERITY_CARDS.map(({ key, label, icon: Icon, color }) => {
                  const count = stats.findings_by_severity[key] || 0;
                  return (
                    <div key={key} style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                      <Icon size={20} color={color} />
                      <span style={{ minWidth: '80px', textTransform: 'capitalize' }}>{label}</span>
                      <div style={{
                        flex: 1,
                        height: '8px',
                        background: 'rgba(255,255,255,0.05)',
                        borderRadius: '4px',
                        overflow: 'hidden',
                      }}>
                        <div style={{
                          width: `${Math.min(100, count * 10)}%`,
                          height: '100%',
                          background: color,
                          borderRadius: '4px',
                          transition: 'width 0.3s ease',
                        }} />
                      </div>
                      <span style={{ fontWeight: 600, minWidth: '30px', textAlign: 'right' }}>{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          {/* Recent Scans & Tool Status */}
          <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: '1.5rem' }}>
            {/* Recent Scans */}
            <div className="glass-card" style={{ padding: '1.5rem' }}>
              <h2 className="heading-2" style={{ margin: 0, marginBottom: '1rem' }}>
                Recent Scans
              </h2>
              {stats?.recent_scans?.length > 0 ? (
                <div className="finding-list">
                  {stats.recent_scans.slice(0, 10).map((scan) => (
                    <div key={scan.scan_id} className="finding-item" style={{ padding: '0.75rem 1rem' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', width: '100%' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Globe size={16} color="var(--accent-primary)" />
                          <span style={{ fontWeight: 500, wordBreak: 'break-all', fontSize: '0.9rem' }}>
                            {scan.target_url}
                          </span>
                        </div>
                        <Link to={`/scans/${scan.scan_id}`} style={{ textDecoration: 'none' }}>
                          <button className="btn btn-outline" style={{ padding: '0.3rem 0.7rem', fontSize: '0.75rem' }}>
                            View
                          </button>
                        </Link>
                      </div>
                      <div style={{ display: 'flex', gap: '1rem', marginTop: '0.4rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                        <Clock size={12} />
                        <span>{new Date(scan.created_at).toLocaleString()}</span>
                        <span>ID: {scan.scan_id.slice(0, 8)}…</span>
                        {scan.status === 'COMPLETED' && scan.overall_score !== null && (
                          <>
                            <ShieldAlert size={12} />
                            <span>Score: {scan.overall_score}/100</span>
                          </>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="empty-state">
                  <FileText size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
                  <div className="empty-title">No scans yet</div>
                  <div className="empty-desc">
                    Create your first security assessment from the New Assessment page.
                  </div>
                  <Link to="/new" style={{ display: 'inline-block', marginTop: '1rem' }}>
                    <button className="btn btn-primary">
                      <Plus size={16} /> Create Assessment
                    </button>
                  </Link>
                </div>
              )}
            </div>

            {/* Tool Status */}
            <div className="glass-card" style={{ padding: '1.5rem' }}>
              <h2 className="heading-2" style={{ margin: 0, marginBottom: '1rem' }}>
                Tool Status
              </h2>
              {tools ? (
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                  {tools.tools.map((t) => (
                    <div key={t.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: '0.9rem', fontWeight: 500 }}>{t.name}</span>
                      <StatusIndicator status={t.available ? 'ready' : 'not_installed'} />
                    </div>
                  ))}
                </div>
              ) : (
                <LoadingSkeleton lines={6} height="20px" />
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
