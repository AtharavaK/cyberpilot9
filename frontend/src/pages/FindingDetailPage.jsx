import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  AlertTriangle, FileText, Code, Globe, Shield, Calendar, Clock,
  Tag, ExternalLink, Copy, CheckCircle2, Loader2, Wrench,
} from 'lucide-react';
import {
  getScanStatus, getScanFindings, getFindingAnalysis, setFindingTriage,
  getRemediationDetails, getScanTriage,
} from '../services/api.js';
import { ErrorBanner, LoadingSkeleton, SeverityBadge, ConfidenceBar } from '../components/ui.jsx';
import { SEVERITY_CONFIG } from '../types/index.js';

const TRIAGE_OPTIONS = [
  { value: 'open', label: 'Open', color: 'var(--text-secondary)' },
  { value: 'confirmed', label: 'Confirmed', color: 'var(--warning)' },
  { value: 'false_positive', label: 'False Positive', color: 'var(--success)' },
  { value: 'accepted', label: 'Accepted Risk', color: 'var(--accent-primary)' },
  { value: 'remediated', label: 'Remediated', color: 'var(--success)' },
];

export default function FindingDetailPage({ scanId: propScanId, findingId: propFindingId }) {
  const navigate = useNavigate();
  const scanId = propScanId || '';
  const findingId = propFindingId != null ? propFindingId : 0;

  const [scan, setScan] = useState(null);
  const [finding, setFinding] = useState(null);
  const [aiAnalysis, setAiAnalysis] = useState(null);
  const [remediation, setRemediation] = useState(null);
  const [loading, setLoading] = useState(true);
  const [aiLoading, setAiLoading] = useState(false);
  const [error, setError] = useState(null);
  const [triageError, setTriageError] = useState(null);
  const [triageSuccess, setTriageSuccess] = useState(null);

  const loadData = async () => {
    setLoading(true);
    setError(null);
    try {
      const [scanRes, findingsRes] = await Promise.allSettled([
        getScanStatus(scanId),
        getScanFindings(scanId),
      ]);

      if (scanRes.status === 'fulfilled') setScan(scanRes.value);

      if (findingsRes.status === 'fulfilled') {
        const data = findingsRes.value;
        const allFindings = [];
        data.by_severity?.forEach(g => {
          g.findings?.forEach(f => allFindings.push(f));
        });
        const found = allFindings.find(f => f.id === findingId) || allFindings[0];
        setFinding(found);
      }
    } catch (err) {
      setError(err.message || 'Failed to load finding');
    } finally {
      setLoading(false);
    }
  };

  const loadAiAnalysis = async () => {
    setAiLoading(true);
    try {
      const data = await getFindingAnalysis(findingId);
      setAiAnalysis(data);
    } catch (err) {
      // AI analysis may not exist yet — not an error for the page
    } finally {
      setAiLoading(false);
    }
  };

  const loadRemediation = async () => {
    try {
      const idx = finding ? parseInt(finding.id || 0) : 0;
      // Find the index of this finding in the scan's findings list
      const data = await getScanFindings(scanId);
      let allFindings = [];
      data.by_severity?.forEach(g => {
        g.findings?.forEach(f => allFindings.push(f));
      });
      const index = allFindings.findIndex(f => f.id === findingId);
      if (index >= 0) {
        const rem = await getRemediationDetails(scanId, index);
        setRemediation(rem);
      }
    } catch (err) {
      // remediation may not be available
    }
  };

  useEffect(() => {
    if (scanId) loadData();
  }, [scanId, findingId]);

  useEffect(() => {
    if (finding) {
      loadAiAnalysis();
      loadRemediation();
    }
  }, [finding]);

  const handleTriage = async (status) => {
    setTriageError(null);
    setTriageSuccess(null);
    try {
      await setFindingTriage(findingId, status, '');
      setTriageSuccess(`Finding marked as ${status}`);
      setTimeout(() => setTriageSuccess(null), 3000);
    } catch (err) {
      setTriageError(err.message || 'Failed to update triage status');
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
  };

  if (loading) return <LoadingSkeleton lines={15} />;

  if (!finding) {
    return (
      <div className="empty-state">
        <FileText size={48} style={{ opacity: 0.2, margin: '0 auto 1rem' }} />
        <div className="empty-title">Finding not found</div>
        <div className="empty-desc">The requested finding could not be located.</div>
      </div>
    );
  }

  const sevCfg = SEVERITY_CONFIG[finding.severity?.toUpperCase()] || SEVERITY_CONFIG.LOW;

  return (
    <div>
      {/* Header */}
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
          <button
            className="btn btn-outline"
            style={{ padding: '0.3rem 0.7rem', fontSize: '0.8rem' }}
            onClick={() => navigate(-1)}
          >
            ← Back
          </button>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <AlertTriangle size={24} color={sevCfg.color} />
          <h1 className="heading-1">{finding.title || 'Untitled Finding'}</h1>
        </div>
      </header>

      {error && <ErrorBanner error={error} />}
      {triageError && <ErrorBanner error={triageError} />}
      {triageSuccess && (
        <div className="glass-card" style={{
          borderLeft: '4px solid var(--success)',
          color: 'var(--success)',
          marginBottom: '1.5rem',
          padding: '0.75rem 1.25rem',
        }}>
          <CheckCircle2 size={16} style={{ marginRight: '0.5rem' }} />
          {triageSuccess}
        </div>
      )}

      {/* Overview Card */}
      <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h2 style={{ margin: '0 0 1rem 0', fontSize: '1.1rem' }}>Overview</h2>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem' }}>
          <div>
            <div className="text-muted" style={{ fontSize: '0.75rem', textTransform: 'uppercase' }}>Severity</div>
            <SeverityBadge severity={finding.severity} size="lg" />
          </div>
          <div>
            <div className="text-muted" style={{ fontSize: '0.75rem', textTransform: 'uppercase' }}>Scanner</div>
            <div style={{ fontSize: '0.9rem', fontWeight: 500 }}>{finding.scanner || finding.agent_name || 'Unknown'}</div>
          </div>
          {finding.confidence != null && (
            <div>
              <div className="text-muted" style={{ fontSize: '0.75rem', textTransform: 'uppercase' }}>Scanner Confidence</div>
              <div style={{ fontSize: '0.9rem', fontWeight: 500 }}>{Math.round(finding.confidence * 100)}%</div>
            </div>
          )}
          {finding.cwe && finding.cwe.length > 0 && (
            <div>
              <div className="text-muted" style={{ fontSize: '0.75rem', textTransform: 'uppercase' }}>CWE</div>
              <div style={{ fontSize: '0.9rem' }}>{finding.cwe.join(', ')}</div>
            </div>
          )}
          {finding.file && (
            <div>
              <div className="text-muted" style={{ fontSize: '0.75rem', textTransform: 'uppercase' }}>File</div>
              <div style={{ fontSize: '0.9rem', fontFamily: 'monospace', wordBreak: 'break-all' }}>{finding.file}</div>
            </div>
          )}
          {finding.line && (
            <div>
              <div className="text-muted" style={{ fontSize: '0.75rem', textTransform: 'uppercase' }}>Line</div>
              <div style={{ fontSize: '0.9rem' }}>{finding.line}</div>
            </div>
          )}
          {finding.target && (
            <div style={{ gridColumn: '1 / -1' }}>
              <div className="text-muted" style={{ fontSize: '0.75rem', textTransform: 'uppercase' }}>Target</div>
              <div style={{ fontSize: '0.9rem', wordBreak: 'break-all' }}>{finding.target}</div>
            </div>
          )}
        </div>
      </div>

      {/* Description & Evidence */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1.5rem', marginBottom: '1.5rem' }}>
        <div className="glass-card" style={{ padding: '1.5rem' }}>
          <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem' }}>Description</h3>
          <p style={{ fontSize: '0.9rem', lineHeight: 1.6, color: 'var(--text-secondary)' }}>
            {finding.description || 'No description available.'}
          </p>
        </div>
        <div className="glass-card" style={{ padding: '1.5rem' }}>
          <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1rem' }}>Evidence</h3>
          <pre style={{
            background: 'rgba(0,0,0,0.2)',
            border: '1px solid var(--glass-border)',
            borderRadius: '6px',
            padding: '0.75rem',
            fontSize: '0.8rem',
            fontFamily: 'monospace',
            overflow: 'auto',
            color: 'var(--text-primary)',
            whiteSpace: 'pre-wrap',
            wordBreak: 'break-all',
          }}>
            {finding.evidence || '[No evidence captured]'}
          </pre>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
            Evidence is displayed as provided. No raw secrets are reconstructed.
          </p>
        </div>
      </div>

      {/* Remediation */}
      <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1.1rem' }}>Remediation</h3>
        {finding.remediation ? (
          <p style={{ fontSize: '0.9rem', lineHeight: 1.6 }}>{finding.remediation}</p>
        ) : (
          <p className="text-muted">No remediation guidance available.</p>
        )}
        {remediation && (
          <div style={{ marginTop: '1rem' }}>
            <h4 style={{ margin: '0 0 0.5rem 0', fontSize: '0.9rem', color: 'var(--accent-primary)' }}>
              Recommended Steps
            </h4>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {remediation.steps?.map((step) => (
                <div key={step.step} style={{ display: 'flex', gap: '0.5rem', fontSize: '0.85rem' }}>
                  <span style={{ fontWeight: 600, color: 'var(--accent-primary)' }}>{step.step}.</span>
                  <div>
                    <strong>{step.title}</strong>
                    <p style={{ margin: '0.2rem 0 0', color: 'var(--text-secondary)' }}>{step.description}</p>
                    {step.command && (
                      <code style={{
                        display: 'block',
                        marginTop: '0.3rem',
                        padding: '0.3rem 0.6rem',
                        background: 'rgba(0,0,0,0.2)',
                        borderRadius: '4px',
                        fontFamily: 'monospace',
                        fontSize: '0.8rem',
                      }}>{step.command}</code>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* AI Analysis */}
      <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
          <h3 style={{ margin: 0, fontSize: '1.1rem' }}>AI Analysis</h3>
          {!aiAnalysis && !aiLoading && (
            <button className="btn btn-outline" style={{ padding: '0.3rem 0.7rem', fontSize: '0.8rem' }}>
              <Wrench size={14} /> Request Analysis
            </button>
          )}
        </div>

        {aiLoading ? (
          <LoadingSkeleton lines={4} />
        ) : aiAnalysis ? (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
            {aiAnalysis.summary && (
              <div>
                <h4 style={{ margin: '0 0 0.3rem 0', fontSize: '0.85rem', color: 'var(--accent-primary)' }}>Summary</h4>
                <p style={{ fontSize: '0.9rem', lineHeight: 1.6 }}>{aiAnalysis.summary}</p>
              </div>
            )}
            {aiAnalysis.risk_explanation && (
              <div>
                <h4 style={{ margin: '0 0 0.3rem 0', fontSize: '0.85rem', color: 'var(--accent-primary)' }}>Risk Explanation</h4>
                <p style={{ fontSize: '0.9rem', lineHeight: 1.6 }}>{aiAnalysis.risk_explanation}</p>
              </div>
            )}
            {aiAnalysis.remediation && (
              <div>
                <h4 style={{ margin: '0 0 0.3rem 0', fontSize: '0.85rem', color: 'var(--accent-primary)' }}>AI Remediation</h4>
                <p style={{ fontSize: '0.9rem', lineHeight: 1.6 }}>{aiAnalysis.remediation}</p>
              </div>
            )}
            <ConfidenceBar
              confidence={aiAnalysis.confidence}
              scannerConfidence={finding.confidence}
            />
            {aiAnalysis.priority != null && (
              <div>
                <span className="badge" style={{ fontSize: '0.75rem' }}>Priority: {aiAnalysis.priority}/10</span>
              </div>
            )}
          </div>
        ) : (
          <p className="text-muted" style={{ fontSize: '0.85rem' }}>
            AI analysis is not available for this finding. If Ollama is running, you can request analysis via the API.
          </p>
        )}
      </div>

      {/* References */}
      {finding.references && finding.references.length > 0 && (
        <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
          <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1.1rem' }}>References</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
            {finding.references.map((ref, i) => {
              const safeRef = ref.startsWith('http://') || ref.startsWith('https://')
                ? ref
                : `https://${ref}`;
              return (
                <a key={i} href={safeRef} target="_blank" rel="noopener noreferrer"
                  style={{ fontSize: '0.85rem', color: 'var(--accent-primary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                  <ExternalLink size={12} />
                  {ref}
                </a>
              );
            })}
          </div>
        </div>
      )}

      {/* Triage */}
      <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h3 style={{ margin: '0 0 0.75rem 0', fontSize: '1.1rem' }}>Triage</h3>
        <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
          {TRIAGE_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              className="btn btn-outline"
              style={{
                padding: '0.4rem 0.8rem',
                fontSize: '0.8rem',
                borderColor: 'rgba(255,255,255,0.1)',
                background: 'rgba(255,255,255,0.02)',
              }}
              onClick={() => handleTriage(opt.value)}
            >
              {opt.label}
            </button>
          ))}
        </div>
      </div>
    </div>
  );
}
