import React, { useState, useEffect } from 'react';
import { Cog, Save, Globe, Key, Shield, Check, AlertCircle, AlertTriangle, Loader2, Plus, Trash2, Copy } from 'lucide-react';
import { listApiKeys, createApiKey, revokeApiKey } from '../services/api.js';

const DEFAULT_API_URL = 'http://localhost:8000/api/v1';

export default function SettingsPanel() {
  const [apiUrl, setApiUrl] = useState(() => {
    return localStorage.getItem('cyberpilot_api_url') || DEFAULT_API_URL;
  });
  const [apiKey, setApiKey] = useState(() => {
    return localStorage.getItem('cyberpilot_api_key') || '';
  });
  const [apiKeySaved, setApiKeySaved] = useState(!!localStorage.getItem('cyberpilot_api_key'));
  const [scanTimeout, setScanTimeout] = useState(() => {
    return parseInt(localStorage.getItem('cyberpilot_scan_timeout') || '300', 10);
  });
  const [theme, setTheme] = useState(() => {
    return localStorage.getItem('cyberpilot_theme') || 'dark';
  });

  // Auto-save API key to localStorage as soon as it changes
  useEffect(() => {
    if (apiKey) {
      localStorage.setItem('cyberpilot_api_key', apiKey);
      setApiKeySaved(true);
    } else {
      localStorage.removeItem('cyberpilot_api_key');
      setApiKeySaved(false);
    }
  }, [apiKey]);
  const [saveStatus, setSaveStatus] = useState(null); // 'saving', 'success', 'error'
  const [testStatus, setTestStatus] = useState(null); // 'testing', 'success', 'error'
  const [testMessage, setTestMessage] = useState('');
  
  // Apply theme on mount and when it changes
  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme);
  }, [theme]);

  // API Key management
  const [apiKeys, setApiKeys] = useState([]);
  const [keysLoading, setKeysLoading] = useState(false);
  const [keysError, setKeysError] = useState(null);
  const [newKeyName, setNewKeyName] = useState('');
  const [creatingKey, setCreatingKey] = useState(false);
  const [showNewKey, setShowNewKey] = useState(null);

  const handleSave = () => {
    setSaveStatus('saving');
    try {
      localStorage.setItem('cyberpilot_api_url', apiUrl);
      localStorage.setItem('cyberpilot_api_key', apiKey);
      localStorage.setItem('cyberpilot_scan_timeout', scanTimeout.toString());
      localStorage.setItem('cyberpilot_theme', theme);
      // Apply theme immediately
      document.documentElement.setAttribute('data-theme', theme);
      setSaveStatus('success');
      setTimeout(() => setSaveStatus(null), 2000);
    } catch (err) {
      setSaveStatus('error');
    }
  };

  const handleTestConnection = async () => {
    setTestStatus('testing');
    setTestMessage('');
    try {
      const res = await fetch(`${apiUrl.replace('/api/v1', '')}/`);
      if (res.ok) {
        setTestStatus('success');
        setTestMessage('Backend API is reachable');
      } else {
        setTestStatus('error');
        setTestMessage(`API returned ${res.status}`);
      }
    } catch (err) {
      setTestStatus('error');
      setTestMessage('Could not connect to backend. Is it running?');
    }
  };

  const handleReset = () => {
    setApiUrl(DEFAULT_API_URL);
    setApiKey('');
    setScanTimeout(300);
    setTheme('dark');
    localStorage.removeItem('cyberpilot_api_url');
    localStorage.removeItem('cyberpilot_api_key');
    localStorage.removeItem('cyberpilot_scan_timeout');
    localStorage.removeItem('cyberpilot_theme');
  };

  const loadApiKeys = async () => {
    setKeysLoading(true);
    setKeysError(null);
    try {
      const keys = await listApiKeys();
      setApiKeys(keys);
    } catch (err) {
      setKeysError(err.message);
    } finally {
      setKeysLoading(false);
    }
  };

  const handleCreateKey = async (e) => {
    e.preventDefault();
    if (!newKeyName.trim()) return;
    setCreatingKey(true);
    try {
      const key = await createApiKey(newKeyName.trim());
      // Store the new key in localStorage so subsequent API calls work
      localStorage.setItem('cyberpilot_api_key', key.key);
      setShowNewKey(key.key);
      setNewKeyName('');
      await loadApiKeys();
    } catch (err) {
      alert('Failed to create API key: ' + err.message);
    } finally {
      setCreatingKey(false);
    }
  };

  const handleRevokeKey = async (keyId) => {
    if (!confirm('Are you sure you want to revoke this API key?')) return;
    try {
      await revokeApiKey(keyId);
      await loadApiKeys();
    } catch (err) {
      alert('Failed to revoke API key: ' + err.message);
    }
  };

  const copyToClipboard = (text) => {
    navigator.clipboard.writeText(text);
    alert('Copied to clipboard!');
  };

  useEffect(() => {
    // Only load API keys if we have an API key stored (bootstrap mode handles first key)
    const storedKey = localStorage.getItem('cyberpilot_api_key');
    if (storedKey) {
      loadApiKeys();
    }
  }, []);

  return (
    <div className="animate-fade-in" style={{ maxWidth: '700px' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '2rem' }}>
        <Cog size={24} color="var(--accent-primary)" />
        <h2 className="heading-2" style={{ margin: 0 }}>Settings</h2>
      </div>

      {/* API Configuration */}
      <div className="glass-card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1.1rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Globe size={20} color="var(--accent-secondary)" />
          API Configuration
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', fontWeight: 500 }}>
              Backend API URL
            </label>
            <input
              type="text"
              value={apiUrl}
              onChange={(e) => setApiUrl(e.target.value)}
              placeholder={DEFAULT_API_URL}
              style={{
                width: '100%',
                padding: '0.75rem 1rem',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid var(--glass-border)',
                borderRadius: '8px',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-main)',
                fontSize: '0.95rem',
                outline: 'none',
              }}
            />
            <p className="text-muted" style={{ marginTop: '0.35rem', fontSize: '0.8rem' }}>
              Base URL for the CyberPilot API (e.g., http://localhost:8000/api/v1)
            </p>
          </div>

          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', fontWeight: 500 }}>
              API Key (for authentication)
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type="password"
                value={apiKey}
                onChange={(e) => setApiKey(e.target.value)}
                placeholder="cpk_... (optional for now)"
                style={{
                  width: '100%',
                  padding: '0.75rem 1rem',
                  background: 'rgba(255,255,255,0.04)',
                  border: `1px solid ${apiKeySaved ? 'var(--success)' : 'var(--glass-border)'}`,
                  borderRadius: '8px',
                  color: 'var(--text-primary)',
                  fontFamily: 'var(--font-main)',
                  fontSize: '0.95rem',
                  outline: 'none',
                  transition: 'border-color 0.3s',
                }}
              />
              {apiKeySaved && (
                <span style={{
                  position: 'absolute',
                  right: '0.75rem',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  color: 'var(--success)',
                  fontSize: '1.1rem',
                }}>
                  ✓
                </span>
              )}
            </div>
            <p className="text-muted" style={{ marginTop: '0.35rem', fontSize: '0.8rem' }}>
              API key for authenticated requests. Format: cpk_xxxxxxxxxxxx
              <br/><span style={{ color: 'var(--warning)', fontSize: '0.75rem' }}>
                Stored in browser localStorage — consider session-only usage for shared machines.
              </span>
            </p>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '1rem', flexWrap: 'wrap' }}>
            <button 
              onClick={handleTestConnection} 
              disabled={testStatus === 'testing'}
              className="btn btn-outline"
              style={{ padding: '0.6rem 1.25rem' }}
            >
              {testStatus === 'testing' ? (
                <>
                  <Loader2 size={16} style={{ animation: 'spin 1s linear infinite' }} />
                  Testing…
                </>
              ) : (
                <>
                  <Shield size={16} />
                  Test Connection
                </>
              )}
            </button>
            {testStatus === 'success' && (
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--success)', fontSize: '0.85rem' }}>
                <Check size={14} /> {testMessage}
              </span>
            )}
            {testStatus === 'error' && (
              <span style={{ display: 'flex', alignItems: 'center', gap: '0.35rem', color: 'var(--error)', fontSize: '0.85rem' }}>
                <AlertCircle size={14} /> {testMessage}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* Scan Settings */}
      <div className="glass-card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1.1rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Shield size={20} color="var(--accent-secondary)" />
          Scan Settings
        </h3>

        <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
          <div>
            <label style={{ display: 'block', marginBottom: '0.5rem', fontSize: '0.9rem', fontWeight: 500 }}>
              Scan Timeout (seconds)
            </label>
            <input
              type="number"
              value={scanTimeout}
              onChange={(e) => setScanTimeout(Math.max(60, parseInt(e.target.value) || 60))}
              min="60"
              max="3600"
              style={{
                width: '100%',
                maxWidth: '200px',
                padding: '0.75rem 1rem',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid var(--glass-border)',
                borderRadius: '8px',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-main)',
                fontSize: '0.95rem',
                outline: 'none',
              }}
            />
            <p className="text-muted" style={{ marginTop: '0.35rem', fontSize: '0.8rem' }}>
              Maximum time to wait for a scan to complete before timing out (60-3600s)
            </p>
          </div>
        </div>
      </div>

      {/* Appearance */}
      <div className="glass-card" style={{ marginBottom: '1.5rem' }}>
        <h3 style={{ fontSize: '1.1rem', marginBottom: '1.5rem', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          <Cog size={20} color="var(--accent-secondary)" />
          Appearance
        </h3>

        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
          {['dark', 'light'].map((t) => (
            <button
              key={t}
              onClick={() => setTheme(t)}
              style={{
                flex: 1,
                minWidth: '140px',
                padding: '1rem 1.5rem',
                borderRadius: '10px',
                border: `2px solid ${theme === t ? 'var(--accent-primary)' : 'rgba(255,255,255,0.05)'}`,
                background: theme === t ? 'rgba(0,240,255,0.08)' : 'rgba(255,255,255,0.02)',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-main)',
                fontWeight: 600,
                fontSize: '0.95rem',
                cursor: 'pointer',
                transition: 'all 0.2s ease',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                gap: '0.5rem',
              }}
            >
              {t === 'dark' ? '🌙' : '☀️'} {t.charAt(0).toUpperCase() + t.slice(1)} Mode
            </button>
          ))}
        </div>
        <p className="text-muted" style={{ marginTop: '0.75rem', fontSize: '0.8rem' }}>
          Note: Light mode styles are not fully implemented in this prototype.
        </p>
      </div>

      {/* API Keys Management */}
      <div className="glass-card" style={{ marginBottom: '1.5rem' }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
          <h3 style={{ fontSize: '1.1rem', margin: 0, display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <Key size={20} color="var(--accent-secondary)" />
            API Keys
          </h3>
          <form onSubmit={handleCreateKey} style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <input
              type="text"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              placeholder="Key name (e.g., production, staging)"
              style={{
                padding: '0.5rem 1rem',
                background: 'rgba(255,255,255,0.04)',
                border: '1px solid var(--glass-border)',
                borderRadius: '6px',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-main)',
                fontSize: '0.9rem',
                outline: 'none',
                minWidth: '180px',
              }}
            />
            <button 
              type="submit"
              disabled={creatingKey || !newKeyName.trim()}
              className="btn btn-primary"
              style={{ padding: '0.5rem 1rem', fontSize: '0.85rem' }}
            >
              {creatingKey ? (
                <>
                  <Loader2 size={14} style={{ animation: 'spin 1s linear infinite' }} />
                  Creating…
                </>
              ) : (
                <>
                  <Plus size={14} />
                  Create Key
                </>
              )}
            </button>
          </form>
        </div>

        {keysError && (
          <div style={{ marginBottom: '1rem', padding: '0.75rem', background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.3)', borderRadius: '6px', color: 'var(--error)', fontSize: '0.85rem' }}>
            {keysError}
          </div>
        )}

        {showNewKey && (
          <div style={{ marginBottom: '1rem', padding: '1rem', background: 'rgba(16,185,129,0.1)', border: '1px solid rgba(16,185,129,0.3)', borderRadius: '8px' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
              <strong style={{ color: 'var(--success)' }}>New API Key Created!</strong>
              <button onClick={() => setShowNewKey(null)} style={{ background: 'none', border: 'none', color: 'var(--text-secondary)', cursor: 'pointer' }}>
                ✕
              </button>
            </div>
            <p className="text-muted" style={{ fontSize: '0.8rem', marginBottom: '0.5rem' }}>
              Copy this key now. It will not be shown again.
            </p>
            <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <code style={{ flex: 1, background: 'rgba(0,0,0,0.3)', padding: '0.5rem', borderRadius: '4px', fontSize: '0.85rem', wordBreak: 'break-all' }}>
                {showNewKey}
              </code>
              <button onClick={() => copyToClipboard(showNewKey)} className="btn btn-outline" style={{ padding: '0.5rem 1rem' }}>
                <Copy size={14} /> Copy
              </button>
              <button onClick={() => setShowNewKey(null)} className="btn btn-outline" style={{ padding: '0.5rem 1rem' }}>
                Done
              </button>
            </div>
          </div>
        )}

        {keysLoading ? (
          <div className="glass-panel" style={{ padding: '2rem', textAlign: 'center' }}>
            <Loader2 size={32} color="var(--accent-primary)" style={{ animation: 'spin 1s linear infinite', margin: '0 auto 1rem' }} />
            <p className="text-muted">Loading API keys…</p>
          </div>
        ) : (
          <div className="finding-list">
            {apiKeys.length === 0 ? (
              <p className="text-muted" style={{ textAlign: 'center', padding: '2rem' }}>
                No API keys yet. Create your first key above.
              </p>
            ) : (
              apiKeys.map((key) => (
                <div key={key.id} className="glass-card" style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '1rem' }}>
                    <div style={{ width: '40px', height: '40px', borderRadius: '8px', background: key.is_active ? 'rgba(16,185,129,0.15)' : 'rgba(239,68,68,0.15)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                      <Key size={20} color={key.is_active ? 'var(--success)' : 'var(--error)'} />
                    </div>
                    <div>
                      <div style={{ fontWeight: 600, color: key.is_active ? 'var(--text-primary)' : 'var(--text-secondary)' }}>
                        {key.name}
                      </div>
                      <div className="text-muted" style={{ fontSize: '0.8rem' }}>
                        Prefix: {key.key_prefix} • Created: {new Date(key.created_at).toLocaleDateString()}
                        {key.last_used && ` • Last used: ${new Date(key.last_used).toLocaleDateString()}`}
                      </div>
                    </div>
                  </div>
                  <div style={{ display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
                    <span className={`badge ${key.is_active ? 'success' : 'error'}`} style={{ fontSize: '0.7rem' }}>
                      {key.is_active ? 'Active' : 'Revoked'}
                    </span>
                    {key.is_active && (
                      <button 
                        onClick={() => handleRevokeKey(key.id)}
                        className="btn btn-outline"
                        style={{ padding: '0.4rem 0.8rem', fontSize: '0.75rem', background: 'rgba(239,68,68,0.1)', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--error)' }}
                      >
                        <Trash2 size={12} /> Revoke
                      </button>
                    )}
                  </div>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* Actions */}
      <div className="glass-card">
        <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap', alignItems: 'center' }}>
          <button 
            onClick={handleSave}
            disabled={saveStatus === 'saving'}
            className="btn btn-primary"
          >
            {saveStatus === 'saving' ? (
              <>
                <Loader2 size={18} style={{ animation: 'spin 1s linear infinite' }} />
                Saving…
              </>
            ) : saveStatus === 'success' ? (
              <>
                <Check size={18} />
                Saved!
              </>
            ) : (
              <>
                <Save size={18} />
                Save Settings
              </>
            )}
          </button>

          <button 
            onClick={handleReset}
            className="btn btn-outline"
            style={{ background: 'rgba(239,68,68,0.1)', borderColor: 'rgba(239,68,68,0.3)', color: 'var(--error)' }}
          >
            Reset to Defaults
          </button>

          {saveStatus === 'success' && (
            <span style={{ color: 'var(--success)', fontSize: '0.85rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
              <Check size={14} /> Settings saved to localStorage
            </span>
          )}
        </div>
      </div>

      {/* Info */}
      <div className="glass-panel" style={{ marginTop: '2rem', padding: '1.5rem' }}>
        <h4 style={{ marginBottom: '0.75rem', fontSize: '0.9rem' }}>About This Prototype</h4>
        <div style={{ fontSize: '0.85rem', lineHeight: 1.7, color: 'var(--text-secondary)' }}>
          <p><strong>CyberPilot v1.0.0</strong> - Autonomous Multi-Agent AI Security Assessment Platform</p>
          <p>Backend: FastAPI + LangGraph + SQLite</p>
          <p>Frontend: React 19 + Vite + Tailwind-like CSS</p>
          <p>Architecture: 10 specialized AI agents orchestrated via LangGraph workflow</p>
          <p style={{ marginTop: '0.5rem' }}>
            <a href="https://github.com" target="_blank" rel="noopener noreferrer" style={{ color: 'var(--accent-primary)' }}>
              View Source (placeholder)
            </a>
          </p>
        </div>
      </div>
    </div>
  );
}