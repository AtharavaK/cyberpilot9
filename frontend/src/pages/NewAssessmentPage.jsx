import React, { useState, useEffect } from 'react';
import { Globe, Shield, AlertTriangle, Lock, Info, Terminal, Target } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { startScan, validateTarget, getToolsStatus } from '../services/api.js';
import { ErrorBanner, StatusIndicator } from '../components/ui.jsx';
import { useApp } from '../context/AppContext.jsx';

const TARGET_KIND_LABELS = {
  web_target: 'Web Target',
  git_repository: 'Git Repository',
  local_path: 'Local Path',
  unknown: 'Unknown',
};

const SCAN_MODES = [
  { value: 'safe', label: 'Safe / Passive', desc: 'Non-intrusive reconnaissance and known-finding analysis. No active scanning.' },
  { value: 'baseline', label: 'Baseline', desc: 'Passive scanning with broader surface coverage.' },
  { value: 'active', label: 'Active', desc: 'Active scanning may send intrusive requests that could affect target behavior.' },
];

export default function NewAssessmentPage() {
  const navigate = useNavigate();
  const { backendReachable } = useApp();

  // Form state
  const [targetUrl, setTargetUrl] = useState('');
  const [targetKind, setTargetKind] = useState('');
  const [targetValid, setTargetValid] = useState(true);
  const [validationMessage, setValidationMessage] = useState('');
  const [scanMode, setScanMode] = useState('safe');
  const [authorize, setAuthorize] = useState(false);
  const [activeScan, setActiveScan] = useState(false);
  const [scanTimeout, setScanTimeout] = useState(300);

  // UI state
  const [error, setError] = useState(null);
  const [isStarting, setIsStarting] = useState(false);
  const [isCheckingTarget, setIsCheckingTarget] = useState(false);
  const [tools, setTools] = useState(null);

  // Validate target on change
  useEffect(() => {
    if (!targetUrl.trim()) {
      setTargetKind('');
      setTargetValid(true);
      setValidationMessage('');
      return;
    }

    const timer = setTimeout(async () => {
      setIsCheckingTarget(true);
      try {
        const result = await validateTarget(targetUrl.trim());
        setTargetKind(result.target_kind || 'unknown');
        setTargetValid(result.valid);
        setValidationMessage(result.error || (result.target_kind ? `Detected: ${TARGET_KIND_LABELS[result.target_kind] || result.target_kind}` : ''));
      } catch (err) {
        // Don't show error if backend unreachable — just skip validation
        setTargetKind('');
        setTargetValid(true);
        setValidationMessage('');
      } finally {
        setIsCheckingTarget(false);
      }
    }, 500);

    return () => clearTimeout(timer);
  }, [targetUrl]);

  // Load tool status
  useEffect(() => {
    getToolsStatus().then(setTools).catch(() => setTools(null));
  }, []);

  const handleStart = async (e) => {
    e.preventDefault();
    setError(null);

    if (!targetUrl.trim()) {
      setError('Please enter a target URL.');
      return;
    }

    if (!targetValid && validationMessage) {
      setError(`Target validation failed: ${validationMessage}`);
      return;
    }

    if (!authorize) {
      setError('You must confirm authorization before starting an assessment.');
      return;
    }

    setIsStarting(true);
    try {
      const simulate = scanMode !== 'active';
      const res = await startScan(
        targetUrl.trim(),
        simulate,
        authorize,
        scanTimeout,
        { scan_mode: scanMode === 'active' ? 'active' : 'connect' },
      );
      navigate(`/scans/${res.scan_id}`);
    } catch (err) {
      setError(err.message || 'Failed to start assessment. Is the backend running?');
    } finally {
      setIsStarting(false);
    }
  };

  const inputError = !targetValid && validationMessage && !targetValid;

  return (
    <div>
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Globe size={24} color="var(--accent-primary)" />
          <h1 className="heading-1">New Assessment</h1>
        </div>
        <p className="text-muted">
          Configure and launch a new security assessment.
        </p>
      </header>

      {!backendReachable && (
        <ErrorBanner
          error="Backend is not reachable. Please check that CyberPilot is running (localhost:8000)."
        />
      )}

      {error && <ErrorBanner error={error} />}

      <form onSubmit={handleStart}>
        {/* Target Input */}
        <div className="glass-card" style={{ marginBottom: '1.5rem', padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Target size={20} color="var(--accent-primary)" />
            Target
          </h2>
          <div className="form-group">
            <label className="form-label">Target URL or Path</label>
            <input
              type="text"
              className={`form-input ${inputError ? 'error' : ''}`}
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="https://example.com"
              disabled={isStarting}
            />
            <div className="form-help">
              Examples: https://example.com, http://localhost:5000, C:\project, https://github.com/user/repo
            </div>
          </div>

          {/* Detected Target Type */}
          {isCheckingTarget && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', fontSize: '0.85rem', color: 'var(--text-secondary)' }}>
              <div style={{ width: '14px', height: '14px', border: '2px solid var(--accent-primary)', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.6s linear infinite' }} />
              Detecting target type…
            </div>
          )}
          {!isCheckingTarget && targetUrl.trim() && targetKind && (
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', padding: '0.5rem 0.75rem', background: 'rgba(0,240,255,0.05)', borderRadius: '6px' }}>
              <Info size={14} color="var(--accent-primary)" />
              <span style={{ fontSize: '0.85rem' }}>
                Detected: <strong>{TARGET_KIND_LABELS[targetKind] || targetKind}</strong>
              </span>
            </div>
          )}
          {!isCheckingTarget && targetUrl.trim() && validationMessage && targetValid && (
            <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
              {validationMessage}
            </div>
          )}
          {!isCheckingTarget && targetUrl.trim() && !targetValid && validationMessage && (
            <div style={{ fontSize: '0.85rem', color: 'var(--error)', marginTop: '0.25rem', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
              <AlertTriangle size={14} /> {validationMessage}
            </div>
          )}
        </div>

        {/* Scan Mode & Authorization */}
        <div className="glass-card" style={{ marginBottom: '1.5rem', padding: '1.5rem' }}>
          <h2 style={{ fontSize: '1.1rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Shield size={20} color="var(--accent-primary)" />
            Assessment Configuration
          </h2>

          {/* Scan Mode */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label className="form-label">Assessment Mode</label>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {SCAN_MODES.map((mode) => {
                const selected = scanMode === mode.value;
                const isDangerous = mode.value === 'active';
                return (
                  <label
                    key={mode.value}
                    style={{
                      display: 'flex',
                      alignItems: 'flex-start',
                      gap: '0.75rem',
                      padding: '0.75rem',
                      borderRadius: '8px',
                      border: selected ? `2px solid ${isDangerous ? 'var(--error)' : 'var(--accent-primary)'}` : '1px solid var(--glass-border)',
                      background: selected ? (isDangerous ? 'rgba(239,68,68,0.05)' : 'rgba(0,240,255,0.05)') : 'transparent',
                      cursor: 'pointer',
                    }}
                  >
                    <input
                      type="radio"
                      name="scanMode"
                      value={mode.value}
                      checked={selected}
                      onChange={() => setScanMode(mode.value)}
                      disabled={isStarting}
                      style={{ marginTop: '0.1rem' }}
                    />
                    <div>
                      <div style={{ fontWeight: 600, color: selected && isDangerous ? 'var(--error)' : 'var(--text-primary)' }}>
                        {mode.label}
                      </div>
                      <div className="form-help" style={{ marginTop: '0.2rem' }}>
                        {mode.desc}
                      </div>
                    </div>
                  </label>
                );
              })}
            </div>
          </div>

          {/* Active Scan Warning */}
          {scanMode === 'active' && (
            <div style={{
              padding: '1rem 1.25rem',
              background: 'rgba(239,68,68,0.08)',
              border: '1px solid rgba(239,68,68,0.3)',
              borderRadius: '8px',
              marginBottom: '1rem',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.5rem' }}>
                <AlertTriangle size={20} color="var(--error)" />
                <strong style={{ color: 'var(--error)' }}>Active Scanning Warning</strong>
              </div>
              <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                Active scanning sends intrusive requests that may cause unexpected behavior
                on the target system. Only enable this for systems you are explicitly
                authorized to test. The backend enforces its own authorization policy
                — selecting active mode does not override safety controls.
              </p>
            </div>
          )}

          {/* Authorization */}
          <div style={{ marginBottom: '1.5rem' }}>
            <label className="form-label" style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Lock size={18} color="var(--accent-primary)" />
              Authorization
            </label>
            <div style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              padding: '0.75rem',
              background: authorize ? 'rgba(0,240,255,0.05)' : 'rgba(245,158,11,0.05)',
              border: `1px solid ${authorize ? 'rgba(0,240,255,0.2)' : 'rgba(245,158,11,0.2)'}`,
              borderRadius: '8px',
            }}>
              <input
                type="checkbox"
                id="authorize"
                checked={authorize}
                onChange={(e) => setAuthorize(e.target.checked)}
                disabled={isStarting}
                style={{ width: '18px', height: '18px' }}
              />
              <label htmlFor="authorize" style={{ cursor: 'pointer', fontSize: '0.9rem' }}>
                I confirm that I am authorized to perform security testing against this target.
              </label>
            </div>
            {authorize && scanMode === 'active' && (
              <div style={{ marginTop: '0.5rem', fontSize: '0.8rem', color: 'var(--text-secondary)', display: 'flex', alignItems: 'center', gap: '0.3rem' }}>
                <Info size={12} />
                Active scanning will be requested — the backend policy may still block it.
              </div>
            )}
          </div>

          {/* Scan Timeout */}
          <div className="form-group">
            <label className="form-label">Scan Timeout (seconds)</label>
            <input
              type="number"
              className="form-input"
              value={scanTimeout}
              onChange={(e) => setScanTimeout(Math.max(60, parseInt(e.target.value) || 60))}
              min="60"
              max="3600"
              disabled={isStarting}
            />
            <div className="form-help">Maximum time to wait for scan completion (60–3600s)</div>
          </div>
        </div>

        {/* Tool Status */}
        {tools && (
          <div className="glass-card" style={{ marginBottom: '1.5rem', padding: '1.5rem' }}>
            <h2 style={{ fontSize: '1.1rem', marginBottom: '1rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
              <Terminal size={20} color="var(--accent-primary)" />
              Tool Status
            </h2>
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
              {tools.tools.map((t) => (
                <div key={t.name} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <div>
                    <span style={{ fontSize: '0.9rem', fontWeight: 500 }}>{t.name}</span>
                    {t.description && (
                      <div className="form-help" style={{ marginTop: '0.1rem' }}>{t.description}</div>
                    )}
                  </div>
                  <StatusIndicator status={
                    t.installed ? 'ready' : (t.available ? 'ready' : 'not_installed')
                  } />
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Submit */}
        <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={isStarting || isCheckingTarget}
            style={{ minWidth: '180px' }}
          >
            {isStarting ? (
              <>
                <div style={{ width: '16px', height: '16px', border: '2px solid currentColor', borderTopColor: 'transparent', borderRadius: '50%', animation: 'spin 0.6s linear infinite', marginRight: '0.5rem' }} />
                Starting Assessment…
              </>
            ) : (
              <>
                <Shield size={18} />
                Start Assessment
              </>
            )}
          </button>
        </div>
      </form>
    </div>
  );
}
