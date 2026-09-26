import React, { useState } from 'react';
import { ShieldAlert, AlertTriangle, Code, Globe, Server, CheckCircle2, Download, FileText } from 'lucide-react';
import { downloadExecutiveSummary, downloadTechnicalReport } from '../services/api.js';

const SEVERITY_MAP = {
  HIGH: { cls: 'error', label: 'High Severity' },
  MEDIUM: { cls: 'warning', label: 'Medium Severity' },
  LOW: { cls: 'success', label: 'Low Severity' },
};

const AGENT_ICON = {
  'AI Security Agent': <Code size={16} />,
  'API Security Agent': <Globe size={16} />,
  'Code Review Agent': <ShieldAlert size={16} />,
  'Infrastructure Agent': <Server size={16} />,
};

export default function LiveResultsPanel({ data }) {
  const [downloading, setDownloading] = useState(null);

  if (!data) return null;

  const { overall_score, findings, target_url, executive_summary_pdf, technical_report_pdf, scan_id, data_source, errors } = data;

  const scoreColor =
    overall_score >= 80
      ? 'var(--success)'
      : overall_score >= 60
      ? 'var(--warning)'
      : 'var(--error)';

  const scoreLabel =
    overall_score >= 80 ? 'Good' : overall_score >= 60 ? 'Fair' : 'Poor';

  const handleDownload = async (type, e) => {
    e.preventDefault();
    e.stopPropagation();
    setDownloading(type);
    try {
      let blob;
      if (type === 'executive') {
        blob = await downloadExecutiveSummary(scan_id);
      } else {
        blob = await downloadTechnicalReport(scan_id);
      }
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${scan_id}_${type === 'executive' ? 'executive_summary' : 'technical_report'}.pdf`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      alert('Failed to download: ' + err.message);
    } finally {
      setDownloading(null);
    }
  };

  return (
    <div className="animate-fade-in">
      {/* Header Stats */}
      <div className="dashboard-grid" style={{ marginBottom: '2rem' }}>
        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div className="text-muted">Overall Security Score</div>
            <ShieldAlert size={22} color={scoreColor} />
          </div>
          <div className="stat-value" style={{ color: scoreColor }}>
            {overall_score}
            <span style={{ fontSize: '1rem', color: 'var(--text-secondary)' }}>/100</span>
          </div>
          <span className={`badge ${SEVERITY_MAP[overall_score >= 80 ? 'LOW' : overall_score >= 60 ? 'MEDIUM' : 'HIGH'].cls}`} style={{ marginTop: '1rem', display: 'inline-block' }}>
            {scoreLabel} Posture
          </span>
        </div>

        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div className="text-muted">Target Application</div>
            <Globe size={22} color="var(--accent-secondary)" />
          </div>
          <div style={{ marginTop: '0.75rem', fontWeight: 600, wordBreak: 'break-all', color: 'var(--accent-primary)', fontSize: '0.95rem' }}>
            {target_url}
          </div>
          <span className="badge success" style={{ marginTop: '1rem', display: 'inline-block' }}>
            <CheckCircle2 size={12} style={{ marginRight: '0.25rem' }} />
            Assessment Complete
          </span>
          {data_source === 'simulation' && (
            <span className="badge warning" style={{ marginLeft: '0.75rem', display: 'inline-block' }}>
              ⚠️ Simulation Mode
            </span>
          )}
        </div>

        <div className="glass-card">
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
            <div className="text-muted">Vulnerabilities Found</div>
            <AlertTriangle size={22} color="var(--error)" />
          </div>
          <div className="stat-value">{findings?.length ?? 0}</div>
          <div style={{ marginTop: '1rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            {['HIGH', 'MEDIUM', 'LOW'].map((sev) => {
              const count = findings?.filter((f) => f.severity === sev).length ?? 0;
              return count > 0 ? (
                <span key={sev} className={`badge ${SEVERITY_MAP[sev].cls}`}>
                  {count} {sev.charAt(0) + sev.slice(1).toLowerCase()}
                </span>
              ) : null;
            })}
          </div>
        </div>
      </div>

      {/* Report Download Buttons */}
      {(executive_summary_pdf || technical_report_pdf) && scan_id && (
        <div className="glass-card" style={{ marginBottom: '1.5rem', padding: '1.5rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
            <FileText size={22} color="var(--accent-primary)" />
            <h3 style={{ margin: 0, fontSize: '1.1rem' }}>Download Reports</h3>
          </div>
          <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
            {executive_summary_pdf && (
              <button 
                onClick={(e) => handleDownload('executive', e)}
                disabled={downloading}
                className="btn btn-outline"
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem 1.25rem' }}
              >
                <Download size={16} />
                {downloading === 'executive' ? (
                  <>
                    <span style={{ animation: 'spin 1s linear infinite' }}>⏳</span>
                    Downloading…
                  </>
                ) : (
                  <>
                    <FileText size={14} />
                    Executive Summary (PDF)
                  </>
                )}
              </button>
            )}
            {technical_report_pdf && (
              <button 
                onClick={(e) => handleDownload('technical', e)}
                disabled={downloading}
                className="btn btn-outline"
                style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.75rem 1.25rem' }}
              >
                <Download size={16} />
                {downloading === 'technical' ? (
                  <>
                    <span style={{ animation: 'spin 1s linear infinite' }}>⏳</span>
                    Downloading…
                  </>
                ) : (
                  <>
                    <FileText size={14} />
                    Technical Report (PDF)
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      )}

      {/* Findings List */}
      {errors && errors.length > 0 && (
        <div className="glass-card" style={{
          borderLeft: '4px solid var(--warning)',
          color: 'var(--warning)',
          marginBottom: '1.5rem',
          padding: '1rem 1.5rem',
        }}>
          <strong>Assessment Warnings:</strong>
          <ul style={{ margin: '0.5rem 0 0', paddingLeft: '1.25rem', color: 'var(--text-secondary)', fontSize: '0.9rem', lineHeight: 1.6 }}>
            {errors.map((err, i) => <li key={i}>{err}</li>)}
          </ul>
        </div>
      )}

      <div className="glass-panel" style={{ padding: '2rem' }}>
        <h2 className="heading-2">Detailed Findings</h2>
        <div className="finding-list">
          {findings?.length > 0 ? (
            findings.map((f, i) => {
              const sev = SEVERITY_MAP[f.severity] || SEVERITY_MAP.LOW;
              return (
                <div key={i} className={`finding-item ${sev.cls === 'error' ? 'high' : sev.cls === 'warning' ? 'medium' : 'low'}`}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                    <h3 style={{ fontSize: '1rem', fontWeight: 600 }}>{f.description}</h3>
                    <span className={`badge ${sev.cls}`}>{sev.label}</span>
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }} className="text-muted">
                    {AGENT_ICON[f.agent_name] ?? <Code size={16} />}
                    {f.agent_name}
                  </div>
                  {f.remediation && (
                    <div style={{ marginTop: '0.5rem', padding: '0.75rem', background: 'rgba(0,0,0,0.2)', borderRadius: '6px', fontSize: '0.9rem', lineHeight: 1.5 }}>
                      <strong style={{ color: 'var(--text-primary)' }}>Remediation: </strong>
                      <span className="text-muted">{f.remediation}</span>
                    </div>
                  )}
                </div>
              );
            })
          ) : (
            <p className="text-muted" style={{ textAlign: 'center', padding: '2rem' }}>
              No findings reported.
            </p>
          )}
        </div>
      </div>
    </div>
  );
}
