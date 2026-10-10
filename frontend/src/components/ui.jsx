import React from 'react';
import { AlertCircle, RefreshCw } from 'lucide-react';
import { SEVERITY_CONFIG, TASK_STATUS_CONFIG } from '../types/index.js';

// ── SeverityBadge ──────────────────────────────────────────────────────────────

/**
 * @param {{severity: string, size?: 'sm'|'md'|'lg'}} props
 */
export function SeverityBadge({ severity, size = 'md' }) {
  const cfg = SEVERITY_CONFIG[severity?.toUpperCase()] || SEVERITY_CONFIG.LOW;
  const sizeClasses = {
    sm: { fontSize: '0.7rem', padding: '0.15rem 0.5rem' },
    md: { fontSize: '0.75rem', padding: '0.25rem 0.75rem' },
    lg: { fontSize: '0.85rem', padding: '0.35rem 1rem' },
  };
  return (
    <span
      className="badge"
      style={{
        ...sizeClasses[size],
        background: cfg.bg,
        color: cfg.color,
        borderColor: cfg.border,
        whiteSpace: 'nowrap',
      }}
    >
      {cfg.label}
    </span>
  );
}

// ── TaskStatusBadge ────────────────────────────────────────────────────────────

/**
 * @param {{status: string, size?: 'sm'|'md'}} props
 */
export function TaskStatusBadge({ status, size = 'md' }) {
  const cfg = TASK_STATUS_CONFIG[status] || TASK_STATUS_CONFIG.pending;
  const sizeClasses = {
    sm: { fontSize: '0.7rem', padding: '0.15rem 0.5rem' },
    md: { fontSize: '0.75rem', padding: '0.25rem 0.6rem' },
  };
  return (
    <span
      className="badge"
      style={{
        ...sizeClasses[size],
        background: cfg.bg,
        color: cfg.color,
        whiteSpace: 'nowrap',
      }}
    >
      {cfg.label}
    </span>
  );
}

// ── StatusIndicator ────────────────────────────────────────────────────────────

/**
 * @param {{status: 'ready'|'unavailable'|'error'|'not_installed'|'running'|'completed'|'pending'}} props
 */
export function StatusIndicator({ status }) {
  const configs = {
    ready:        { color: 'var(--success)', text: 'Ready', dot: true },
    unavailable:  { color: 'var(--warning)', text: 'Unavailable', dot: true },
    error:        { color: 'var(--error)', text: 'Error', dot: true },
    not_installed: { color: 'var(--text-secondary)', text: 'Not Installed', dot: true },
    running:      { color: 'var(--accent-primary)', text: 'Running', dot: true, pulse: true },
    completed:    { color: 'var(--success)', text: 'Completed', dot: true },
    pending:      { color: 'var(--text-secondary)', text: 'Pending', dot: true },
    blocked:      { color: 'var(--error)', text: 'Blocked', dot: true },
    skipped:      { color: 'var(--text-secondary)', text: 'Skipped', dot: true },
  };
  const cfg = configs[status] || configs.pending;
  return (
    <span
      data-testid="status-indicator"
      style={{
        display: 'inline-flex',
      alignItems: 'center',
      gap: '0.35rem',
      fontSize: '0.8rem',
      color: cfg.color,
    }}>
      <span style={{
        width: '8px',
        height: '8px',
        borderRadius: '50%',
        background: cfg.color,
        animation: cfg.pulse ? 'pulse 1.5s ease-in-out infinite' : 'none',
      }} />
      <span>{cfg.text}</span>
    </span>
  );
}

// ── ErrorBanner ────────────────────────────────────────────────────────────────

/**
 * @param {{error: string|object, onRetry?: function}} props
 */
export function ErrorBanner({ error, onRetry }) {
  if (!error) return null;
  const message = typeof error === 'string' ? error : (error?.message || 'An unknown error occurred');
  return (
    <div className="glass-card animate-fade-in" style={{
      borderLeft: '4px solid var(--error)',
      color: 'var(--error)',
      marginBottom: '1.5rem',
      padding: '1rem 1.5rem',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
        <AlertCircle size={20} />
        <strong>Error</strong>
      </div>
      <p style={{ marginTop: '0.5rem', fontSize: '0.9rem' }}>{message}</p>
      {onRetry && (
        <button
          onClick={onRetry}
          className="btn btn-outline"
          style={{ marginTop: '0.75rem', padding: '0.4rem 0.8rem', fontSize: '0.8rem' }}
        >
          <RefreshCw size={14} /> Retry
        </button>
      )}
    </div>
  );
}

// ── LoadingSkeleton ────────────────────────────────────────────────────────────

export function LoadingSkeleton({ lines = 3, height = '1rem' }) {
  return (
    <div data-testid="loading-skeleton" style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
      {Array.from({ length: lines }).map((_, i) => (
        <div
          key={i}
          className="glass-card"
          style={{
            height,
            width: i === lines - 1 ? '60%' : '100%',
            animation: 'pulse 1.5s ease-in-out infinite',
            opacity: 0.5 + (i * 0.1),
          }}
        />
      ))}
    </div>
  );
}

// ── ConfidenceBar ──────────────────────────────────────────────────────────────

/**
 * @param {{confidence: number|null, scannerConfidence?: number|null}} props
 * confidence is 0.0-1.0 scale
 */
export function ConfidenceBar({ confidence, scannerConfidence }) {
  const aiConf = confidence != null ? Math.round(confidence * 100) : null;
  const scnrConf = scannerConfidence != null ? Math.round(scannerConfidence * 100) : null;

  const barColor = (c) => {
    if (c == null) return 'var(--text-secondary)';
    if (c >= 80) return 'var(--success)';
    if (c >= 60) return 'var(--warning)';
    return 'var(--error)';
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
      {scnrConf != null && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '0.15rem' }}>
            <span className="text-muted">Scanner Confidence</span>
            <span style={{ color: barColor(scnrConf) }}>{scnrConf}%</span>
          </div>
          <ConfidenceBarInner value={scnrConf} color={barColor(scnrConf)} />
        </div>
      )}
      {aiConf != null && (
        <div>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', marginBottom: '0.15rem' }}>
            <span className="text-muted">AI Confidence</span>
            <span style={{ color: barColor(aiConf) }}>{aiConf}%</span>
          </div>
          <ConfidenceBarInner value={aiConf} color={barColor(aiConf)} />
        </div>
      )}
    </div>
  );
}

function ConfidenceBarInner({ value, color }) {
  const pct = Math.max(0, Math.min(100, value));
  return (
    <div style={{
      width: '100%',
      height: '6px',
      background: 'rgba(255,255,255,0.05)',
      borderRadius: '3px',
      overflow: 'hidden',
    }}>
      <div style={{
        width: `${pct}%`,
        height: '100%',
        background: color,
        borderRadius: '3px',
        transition: 'width 0.3s ease',
      }} />
    </div>
  );
}

// ── useApi hook ────────────────────────────────────────────────────────────────

import { useState, useCallback } from 'react';

export function useApi(asyncFn, options = {}) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const execute = useCallback(async (...args) => {
    setLoading(true);
    setError(null);
    try {
      const result = await asyncFn(...args);
      setData(result);
      return result;
    } catch (err) {
      setError(err);
      if (!options.silent) throw err;
      return null;
    } finally {
      setLoading(false);
    }
  }, [asyncFn, options.silent]);

  return { data, loading, error, execute };
}
