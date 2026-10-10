import React, { useEffect, useState } from 'react';
import { FileText, Download, Calendar, ShieldAlert, Globe, CheckCircle2, Loader2 } from 'lucide-react';
import { listAllScans, downloadExecutiveSummary, downloadTechnicalReport } from '../services/api.js';
import { ErrorBanner, LoadingSkeleton, StatusIndicator } from '../components/ui.jsx';

export default function ReportsPage() {
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
      setError(err.message || 'Failed to load scans');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadScans();
  }, []);

  const completedScans = scans.filter(s => s.status === 'COMPLETED');

  const handleDownload = async (scanId, type) => {
    setDownloading(`${scanId}-${type}`);
    try {
      let blob;
      if (type === 'executive') {
        blob = await downloadExecutiveSummary(scanId);
      } else {
        blob = await downloadTechnicalReport(scanId);
      }
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${scanId}_${type === 'executive' ? 'executive_summary' : 'technical_report'}.pdf`;
      a.click();
      window.URL.revokeObjectURL(url);
    } catch (err) {
      alert('Failed to download: ' + err.message);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div>
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <FileText size={24} color="var(--accent-primary)" />
          <h1 className="heading-1">Reports</h1>
        </div>
        <p className="text-muted">
          Generate and download PDF reports for completed assessments.
        </p>
      </header>

      {error && <ErrorBanner error={error} onRetry={loadScans} />}

      {loading ? (
        <LoadingSkeleton lines={8} />
      ) : completedScans.length === 0 ? (
        <div className="empty-state">
          <FileText size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
          <div className="empty-title">No reports available</div>
          <div className="empty-desc">
            Reports are generated when a security assessment completes.
          </div>
        </div>
      ) : (
        <div className="finding-list">
          {completedScans.map((scan) => (
            <div key={scan.scan_id} className="glass-card" style={{ padding: '1.5rem', marginBottom: '1rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '1rem' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <Globe size={20} color="var(--accent-primary)" />
                  <div>
                    <div style={{ fontWeight: 600, fontSize: '0.95rem', wordBreak: 'break-all' }}>{scan.target_url}</div>
                    <div className="text-muted" style={{ fontSize: '0.8rem' }}>
                      <Calendar size={12} style={{ marginRight: '0.3rem' }} />
                      {new Date(scan.created_at).toLocaleString()}
                    </div>
                  </div>
                </div>
                <StatusIndicator status="completed" />
              </div>

              <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap', marginBottom: '1rem' }}>
                <div>
                  <span className="text-muted" style={{ fontSize: '0.75rem' }}>Security Score</span>
                  <div style={{ fontSize: '1.4rem', fontWeight: 700 }}>
                    {scan.overall_score ?? 'N/A'}
                    {scan.overall_score != null && <span style={{ fontSize: '0.8rem', color: 'var(--text-secondary)' }}>/100</span>}
                  </div>
                </div>
              </div>

              <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
                <button
                  className="btn btn-outline"
                  style={{ padding: '0.5rem 1rem' }}
                  onClick={() => handleDownload(scan.scan_id, 'executive')}
                  disabled={downloading === `${scan.scan_id}-executive`}
                >
                  {downloading === `${scan.scan_id}-executive` ? (
                    <Loader2 size={16} style={{ animation: 'spin 0.6s linear infinite', marginRight: '0.5rem' }} />
                  ) : (
                    <Download size={16} style={{ marginRight: '0.5rem' }} />
                  )}
                  Executive Summary (PDF)
                </button>
                <button
                  className="btn btn-outline"
                  style={{ padding: '0.5rem 1rem' }}
                  onClick={() => handleDownload(scan.scan_id, 'technical')}
                  disabled={downloading === `${scan.scan_id}-technical`}
                >
                  {downloading === `${scan.scan_id}-technical` ? (
                    <Loader2 size={16} style={{ animation: 'spin 0.6s linear infinite', marginRight: '0.5rem' }} />
                  ) : (
                    <Download size={16} style={{ marginRight: '0.5rem' }} />
                  )}
                  Technical Report (PDF)
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
