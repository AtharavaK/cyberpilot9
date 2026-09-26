import React, { useState } from 'react';
import { Globe, Play, Loader2, Lock } from 'lucide-react';

export default function ScanForm({ onScanStart, isScanning, scanTimeout }) {
  const [url, setUrl] = useState('');
  const [error, setError] = useState('');
  const [useRealTools, setUseRealTools] = useState(false);

  const handleSubmit = (e) => {
    e.preventDefault();
    setError('');
    if (!url.trim()) {
      setError('Please enter a target URL.');
      return;
    }
    try {
      new URL(url);
    } catch {
      setError('Please enter a valid URL (e.g., https://example.com).');
      return;
    }
    // Simulation is the safe default. Real tools require explicit opt-in
    // AND a valid API key (backend enforces authorize=True for real scans).
    onScanStart(url.trim(), !useRealTools, useRealTools);
  };

  return (
    <div className="glass-card animate-fade-in" style={{ marginBottom: '2rem' }}>
      <h2 className="heading-2" style={{ marginBottom: '0.5rem' }}>New Security Assessment</h2>
      <p className="text-muted" style={{ marginBottom: '1.5rem' }}>
        Enter the target URL to begin the autonomous multi-agent analysis.
      </p>
      <form onSubmit={handleSubmit} style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ flex: 1, position: 'relative', minWidth: '280px' }}>
          <Globe
            size={18}
            style={{
              position: 'absolute',
              left: '1rem',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--text-secondary)',
              pointerEvents: 'none',
            }}
          />
          <input
            type="text"
            placeholder="https://target-ai-app.com"
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            disabled={isScanning}
            style={{
              width: '100%',
              padding: '0.75rem 1rem 0.75rem 2.75rem',
              background: 'rgba(255,255,255,0.04)',
              border: `1px solid ${error ? 'var(--error)' : 'var(--glass-border)'}`,
              borderRadius: '8px',
              color: 'var(--text-primary)',
              fontFamily: 'var(--font-main)',
              fontSize: '0.95rem',
              outline: 'none',
              transition: 'border-color 0.2s',
            }}
            onFocus={(e) => (e.target.style.borderColor = 'var(--accent-primary)')}
            onBlur={(e) =>
              (e.target.style.borderColor = error ? 'var(--error)' : 'var(--glass-border)')
            }
          />
        </div>
        <button type="submit" className="btn btn-primary" disabled={isScanning}>
          {isScanning ? (
            <>
              <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
              Scanning…
            </>
          ) : (
            <>
              <Play size={18} />
              Start Assessment
            </>
          )}
        </button>
      </form>
      {/* Mode toggle — simulation is safe default; real tools need API key + explicit opt-in */}
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginTop: '1rem' }}>
        <button
          type="button"
          onClick={() => setUseRealTools(!useRealTools)}
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.5rem 1rem',
            borderRadius: '8px',
            border: `1px solid ${useRealTools ? 'var(--accent-primary)' : 'var(--glass-border)'}`,
            background: useRealTools ? 'rgba(0,240,255,0.08)' : 'transparent',
            color: useRealTools ? 'var(--accent-primary)' : 'var(--text-secondary)',
            fontFamily: 'var(--font-main)',
            fontSize: '0.85rem',
            cursor: 'pointer',
            transition: 'all 0.2s',
          }}
        >
          {useRealTools && <Lock size={14} />}
          {useRealTools ? 'Real Tools (auth required)' : 'Simulation mode'}
        </button>
        {useRealTools && (
          <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', margin: 0 }}>
            Requires a valid API key. Backend enforces authorization for real scans.
          </p>
        )}
      </div>
      {error && (
        <p style={{ marginTop: '0.75rem', color: 'var(--error)', fontSize: '0.85rem' }}>{error}</p>
      )}
    </div>
  );
}
