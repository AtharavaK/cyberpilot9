import React, { useEffect, useState } from 'react';
import { FileText, Globe, Clock, ShieldAlert, Loader2, RefreshCw, Download, BarChart3 } from 'lucide-react';
import { Link } from 'react-router-dom';
import { listAllScans, downloadExecutiveSummary } from '../services/api.js';
import { ErrorBanner, LoadingSkeleton, StatusIndicator } from '../components/ui.jsx';
import { SCAN_STATUS_LABELS } from '../types/index.js';

export default function ScanHistoryPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [downloading, setDownloading] = useState(null);

  const loadScans = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listAllScans();
      setScans(data);
    } catch (err) {
      if (err.status === 401) {
        setError('Authentication required. Please create an API key in Settings.');
      } else {
        setError(err.message || 'Failed to load scan history');
      }
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  const handleDownload = async (scanId) => {
    setDownloading(scanId);
    try {
      const blob = await downloadExecutiveSummary(scanId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${scanId}_executive_summary.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download: ' + err.message);
    } finally {
      setDownloading(null);
    }
  };

  const getStatusColor = (status) => {
    if (status === 'COMPLETED') return 'var(--success)';
    if (status === 'FAILED' || status === 'CANCELLED') return 'var(--error)';
    if (status === 'PAUSED') return 'var(--warning)';
    return 'var(--accent-primary)';
  };

  if (loading) return <LoadingSkeleton lines={10} />;

  if (error) {
    return (
      <div>
        <header style={{ marginBottom: '2rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
            <FileText size={24} color="var(--accent-primary)" />
            <h1 className="heading-1">Scan History</h1>
          </div>
        </header>
        <ErrorBanner error={error} onRetry={loadScans} />
      </div>
    );
  }

  return (
    <div>
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <FileText size={24} color="var(--accent-primary)" />
          <h1 className="heading-1">Scan History</h1>
        </div>
        <p className="text-muted">All security assessments performed on this instance.</p>
      </header>

      {scans.length === 0 ? (
        <div className="empty-state">
          <FileText size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
          <div className="empty-title">No scans yet</div>
          <div className="empty-desc">
            Run your first assessment from the New Assessment page.
          </div>
          <Link to="/new" style={{ display: 'inline-block', marginTop: '1.5rem' }}>
            <button className="btn btn-primary">
              Create First Assessment
            </button>
          </Link>
        </div>
      ) : (
        <div className="glass-card" style={{ padding: '1.5rem' }}>
          <table className="table">
            <thead>
              <tr>
                <th>Target</th>
                <th>Started</th>
                <th>Duration</th>
                <th>Status</th>
                <th>Findings</th>
                <th>Score</th>
                <th style={{ textAlign: 'right' }}>Actions</th>
              </tr>
            </thead>
            <tbody>
              {scans.map((scan) => {
                const statusColor = getStatusColor(scan.status);
                const isTerminal = scan.status === 'COMPLETED' || scan.status === 'FAILED' ||
                                   scan.status === 'CANCELLED' || scan.status === 'TIMEOUT';
                return (
                  <tr key={scan.scan_id}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                        <Globe size={14} color={statusColor} />
                        <span style={{ fontWeight: 500, wordBreak: 'break-all', fontSize: '0.9rem' }}>
                          {scan.target_url}
                        </span>
                      </div>
                      <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.2rem' }}>
                        {scan.scan_id.slice(0, 8)}…
                      </div>
                    </td>
                    <td className="text-muted" style={{ fontSize: '0.85rem' }}>
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="text-muted" style={{ fontSize: '0.85rem' }}>
                      {isTerminal ? '—' : 'Running…'}
                    </td>
                    <td>
                      <StatusIndicator status={
                        scan.status === 'COMPLETED' ? 'completed' :
                        scan.status === 'FAILED' || scan.status === 'CANCELLED' ? 'error' :
                        scan.status === 'PAUSED' ? 'pending' : 'running'
                      } />
                      <div className="text-muted" style={{ fontSize: '0.75rem', marginTop: '0.2rem' }}>
                        {SCAN_STATUS_LABELS[scan.status] || scan.status}
                      </div>
                    </td>
                    <td>
                      {isTerminal && scan.overall_score !== null ? (
                        <span style={{ fontWeight: 600, color: statusColor }}>{scan.overall_score}/100</span>
                      ) : (
                        '—'
                      )}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <div style={{ display: 'flex', gap: '0.25rem', justifyContent: 'flex-end' }}>
                        {isTerminal && (
                          <button
                            className="btn btn-outline"
                            style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}
                            onClick={() => handleDownload(scan.scan_id)}
                            disabled={downloading === scan.scan_id}
                            title="Download executive summary"
                          >
                            {downloading === scan.scan_id ? (
                              <Loader2 size={12} style={{ animation: 'spin 0.6s linear infinite' }} />
                            ) : (
                              <Download size={12} />
                            )}
                          </button>
                        )}
                        <Link to={`/scans/${scan.scan_id}`}>
                          <button className="btn btn-outline" style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem' }}>
                            View
                          </button>
                        </Link>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
