import React, { useEffect, useState } from 'react';
import { Key, Save, Trash2, Copy, Check, Plus, RefreshCw, Settings, Shield, Server, AlertCircle } from 'lucide-react';
import { listApiKeys, createApiKey, revokeApiKey, getApiKey, checkHealth, getAiStatus } from '../services/api.js';
import { ErrorBanner, LoadingSkeleton, StatusIndicator } from '../components/ui.jsx';

export default function SettingsPage() {
  const [apiKeys, setApiKeys] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [creating, setCreating] = useState(false);
  const [newKeyName, setNewKeyName] = useState('');
  const [newKeyResult, setNewKeyResult] = useState(null);
  const [copied, setCopied] = useState(null);
  const [health, setHealth] = useState(null);
  const [aiStatus, setAiStatus] = useState(null);

  const loadApiKeys = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await listApiKeys();
      setApiKeys(data);
    } catch (err) {
      setError(err.message || 'Failed to load API keys');
    } finally {
      setLoading(false);
    }
  };

  const loadHealth = async () => {
    try {
      const data = await checkHealth();
      setHealth(data);
    } catch (err) {
      setHealth({ status: 'unhealthy', error: err.message });
    }
  };

  const loadAiStatus = async () => {
    try {
      const data = await getAiStatus();
      setAiStatus(data);
    } catch (err) {
      setAiStatus({ ai_enabled: false, error: err.message });
    }
  };

  useEffect(() => {
    loadApiKeys();
    loadHealth();
    loadAiStatus();
  }, []);

  const handleCreateKey = async () => {
    if (!newKeyName.trim()) return;
    setCreating(true);
    setNewKeyResult(null);
    try {
      const data = await createApiKey(newKeyName);
      setNewKeyResult(data);
      setNewKeyName('');
      loadApiKeys();
    } catch (err) {
      alert('Failed to create API key: ' + err.message);
    } finally {
      setCreating(false);
    }
  };

  const handleRevoke = async (keyId) => {
    if (!confirm('Revoke this API key?')) return;
    try {
      await revokeApiKey(keyId);
      loadApiKeys();
    } catch (err) {
      alert('Failed: ' + err.message);
    }
  };

  const handleCopyKey = (key) => {
    navigator.clipboard.writeText(key);
    setCopied(key);
    setTimeout(() => setCopied(null), 3000);
  };

  const storedKey = getApiKey();

  return (
    <div>
      <header style={{ marginBottom: '2rem' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <Settings size={24} color="var(--accent-primary)" />
          <h1 className="heading-1">Settings</h1>
        </div>
        <p className="text-muted">Manage API keys, check service status, and configure your CyberPilot instance.</p>
      </header>

      {/* Health Status */}
      <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h2 className="heading-2" style={{ margin: '0 0 1rem 0', fontSize: '1rem' }}>Service Status</h2>
        <div style={{ display: 'flex', gap: '2rem', flexWrap: 'wrap' }}>
          <div>
            <span className="text-muted" style={{ fontSize: '0.8rem' }}>Backend</span>
            <StatusIndicator status={health?.status === 'ok' ? 'ready' : health?.status === 'error' ? 'error' : 'loading'} />
          </div>
          <div>
            <span className="text-muted" style={{ fontSize: '0.8rem' }}>AI Engine</span>
            <StatusIndicator status={aiStatus?.ai_ready ? 'ready' : 'not_installed'} />
            {aiStatus?.model && <span className="text-muted" style={{ fontSize: '0.8rem', marginLeft: '0.5rem' }}>{aiStatus.model}</span>}
          </div>
        </div>
      </div>

      {/* API Key Management */}
      <div className="glass-card" style={{ padding: '1.5rem', marginBottom: '1.5rem' }}>
        <h2 className="heading-2" style={{ margin: '0 0 1rem 0' }}>API Keys</h2>

        {error && <ErrorBanner error={error} onRetry={loadApiKeys} />}

        {loading ? (
          <LoadingSkeleton lines={4} height="50px" />
        ) : (
          <div>
            {/* Currently active key */}
            {storedKey && (
              <div style={{
                padding: '0.75rem',
                background: 'rgba(0,123,255,0.08)',
                border: '1px solid rgba(0,123,255,0.3)',
                borderRadius: '8px',
                marginBottom: '1rem',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                  <Check size={16} color="var(--accent-primary)" />
                  <span style={{ fontWeight: 500, fontSize: '0.85rem' }}>Active key configured</span>
                </div>
                <div style={{
                  fontFamily: 'monospace',
                  fontSize: '0.8rem',
                  marginTop: '0.5rem',
                  wordBreak: 'break-all',
                  opacity: 0.7,
                }}>
                  {storedKey.slice(0, 8)}…{storedKey.slice(-4)}
                </div>
              </div>
            )}

            {/* Key list */}
            <table className="table" style={{ marginBottom: '1.5rem' }}>
              <thead>
                <tr>
                  <th>Name</th>
                  <th>Created</th>
                  <th style={{ textAlign: 'right' }}>Actions</th>
                </tr>
              </thead>
              <tbody>
                {(Array.isArray(apiKeys) ? apiKeys : []).map((key) => (
                  <tr key={key.id}>
                    <td style={{ fontWeight: 500 }}>{key.name}</td>
                    <td className="text-muted" style={{ fontSize: '0.85rem' }}>
                      {new Date(key.created_at).toLocaleString()}
                    </td>
                    <td style={{ textAlign: 'right' }}>
                      <button
                        className="btn btn-outline"
                        style={{ padding: '0.3rem 0.6rem', fontSize: '0.75rem', color: 'var(--error)', borderColor: 'var(--error)' }}
                        onClick={() => handleRevoke(key.id)}
                        title="Revoke this API key"
                      >
                        <Trash2 size={12} />
                      </button>
                    </td>
                  </tr>
                ))}
                {(Array.isArray(apiKeys) && apiKeys.length === 0) && (
                  <tr>
                    <td colSpan="3" style={{ textAlign: 'center', color: 'var(--text-secondary)' }}>
                      No API keys created yet.
                    </td>
                  </tr>
                )}
              </tbody>
            </table>

            {/* New key form */}
            <div style={{
              padding: '1rem',
              background: 'rgba(0,255,136,0.05)',
              border: '1px solid rgba(0,255,136,0.15)',
              borderRadius: '8px',
            }}>
              <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                <Plus size={16} color="var(--success)" />
                <input
                  type="text"
                  className="input"
                  placeholder="New API key name"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleCreateKey()}
                  style={{ flex: 1, padding: '0.4rem 0.7rem', fontSize: '0.85rem' }}
                />
                <button
                  className="btn btn-primary"
                  style={{ padding: '0.4rem 1rem', fontSize: '0.85rem' }}
                  onClick={handleCreateKey}
                  disabled={creating || !newKeyName.trim()}
                >
                  {creating ? <RefreshCw size={14} style={{ animation: 'spin 0.6s linear infinite', marginRight: '0.3rem' }} /> : <Plus size={14} style={{ marginRight: '0.3rem' }} />}
                  Create Key
                </button>
              </div>
            </div>

            {/* New key result */}
            {newKeyResult && (
              <div style={{
                marginTop: '1rem',
                padding: '1rem',
                background: 'rgba(255,193,7,0.08)',
                border: '1px solid rgba(255,193,7,0.3)',
                borderRadius: '8px',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.75rem' }}>
                  <AlertCircle size={16} color="var(--warning)" />
                  <strong style={{ fontSize: '0.9rem' }}>API key created — save it now</strong>
                </div>
                <div style={{
                  fontFamily: 'monospace',
                  fontSize: '0.85rem',
                  padding: '0.5rem',
                  background: 'rgba(0,0,0,0.2)',
                  borderRadius: '6px',
                  wordBreak: 'break-all',
                  marginBottom: '0.5rem',
                }}>
                  {newKeyResult.key}
                </div>
                <button
                  className="btn btn-outline"
                  style={{ padding: '0.3rem 0.8rem', fontSize: '0.8rem' }}
                  onClick={() => handleCopyKey(newKeyResult.key)}
                >
                  {copied === newKeyResult.key ? <Check size={14} /> : <Copy size={14} style={{ marginRight: '0.3rem' }} />}
                  {copied === newKeyResult.key ? 'Copied!' : 'Copy to clipboard'}
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {/* API Endpoint Configuration */}
      <div className="glass-card" style={{ padding: '1.5rem' }}>
        <h2 className="heading-2" style={{ margin: '0 0 1rem 0' }}>Backend Configuration</h2>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <span className="text-muted" style={{ fontSize: '0.85rem', minWidth: '120px' }}>Endpoint:</span>
            <code style={{
              background: 'rgba(0,0,0,0.2)',
              padding: '0.25rem 0.6rem',
              borderRadius: '4px',
              fontSize: '0.85rem',
              fontFamily: 'monospace',
            }}>
              {window.location.origin.replace('/app', '')}
            </code>
          </div>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <span className="text-muted" style={{ fontSize: '0.85rem', minWidth: '120px' }}>API Key:</span>
            <span style={{ fontFamily: 'monospace', fontSize: '0.85rem' }}>
              {storedKey ? `${storedKey.slice(0, 8)}…${storedKey.slice(-4)}` : 'Not set'}
            </span>
          </div>
          <div style={{ display: 'flex', gap: '1rem', alignItems: 'center' }}>
            <span className="text-muted" style={{ fontSize: '0.85rem', minWidth: '120px' }}>AI Analysis:</span>
            <span style={{ fontSize: '0.85rem' }}>
              {aiStatus?.ai_enabled ? 'Enabled' : 'Disabled (simulation mode)'}
            </span>
          </div>
        </div>
      </div>
    </div>
  );
}
