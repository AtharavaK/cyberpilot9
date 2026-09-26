import React, { useState, useEffect, useRef } from 'react';
import {
  ShieldAlert,
  Activity,
  FileText,
  Bot,
  Cog,
} from 'lucide-react';
import './index.css';
import { startScan, getScanStatus } from './services/api.js';
import ScanForm from './components/ScanForm.jsx';
import AgentProgress from './components/AgentProgress.jsx';
import LiveResultsPanel from './components/LiveResultsPanel.jsx';
import ScanHistory from './components/ScanHistory.jsx';
import AgentsPanel from './components/AgentsPanel.jsx';
import SettingsPanel from './components/SettingsPanel.jsx';

const POLL_INTERVAL_MS = 2000;

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  // Scan state
  const [isScanning, setIsScanning] = useState(false);
  const [scanId, setScanId] = useState(null);
  const [scanStatus, setScanStatus] = useState(null);
  const [scanResult, setScanResult] = useState(null);
  const [scanError, setScanError] = useState(null);
  const [apiReachable, setApiReachable] = useState(true);

  const pollRef = useRef(null);

  // Stop polling helper
  const stopPolling = () => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  };

  // Poll for scan status
  useEffect(() => {
    if (!scanId || !isScanning) return;

    pollRef.current = setInterval(async () => {
      try {
        const data = await getScanStatus(scanId);
        setApiReachable(true);
        setScanStatus(data.status);

        // Handle terminal states
        if (data.status === 'COMPLETED') {
          setScanResult(data);
          setIsScanning(false);
          stopPolling();
        } else if (data.status === 'FAILED' || data.status === 'ERROR') {
          setScanError(data.message || 'Scan failed');
          setIsScanning(false);
          stopPolling();
        }
      } catch (err) {
        setApiReachable(false);
        console.error('Polling error:', err);
      }
    }, POLL_INTERVAL_MS);

    return () => stopPolling();
  }, [scanId, isScanning]);

  const handleScanStart = async (url) => {
    setScanError(null);
    setScanResult(null);
    setScanStatus(null);
    setIsScanning(true);
    try {
      const res = await startScan(url);
      setScanId(res.scan_id);
      setScanStatus('INITIALIZING');
      setApiReachable(true);
    } catch (err) {
      if (err.status === 401) {
        setScanError('Authentication required. Please add an API key in Settings tab.');
      } else {
        setScanError(err.message || 'Could not connect to the CyberPilot API. Make sure the backend is running.');
      }
      setIsScanning(false);
      setApiReachable(err.status !== 401);
    }
  };

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand">
          <ShieldAlert size={28} color="var(--accent-primary)" />
          CyberPilot
        </div>

        <nav style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
          {[
            { key: 'dashboard', icon: <Activity size={20} />, label: 'Dashboard' },
            { key: 'agents', icon: <Bot size={20} />, label: 'AI Agents' },
            { key: 'reports', icon: <FileText size={20} />, label: 'Reports' },
            { key: 'settings', icon: <Cog size={20} />, label: 'Settings' },
          ].map(({ key, icon, label }) => (
            <div
              key={key}
              className={`nav-item ${activeTab === key ? 'active' : ''}`}
              onClick={() => setActiveTab(key)}
            >
              {icon}
              {label}
            </div>
          ))}
        </nav>

        {/* API Status indicator */}
        <div style={{ marginTop: 'auto', display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
          {apiReachable ? (
            <span style={{ fontSize: '1rem' }}>🟢</span>
          ) : (
            <span style={{ fontSize: '1rem' }}>🔴</span>
          )}
          <span className="text-muted" style={{ fontSize: '0.8rem' }}>
            {apiReachable ? 'API Connected' : 'API Offline'}
          </span>
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <header style={{ marginBottom: '2rem' }}>
          <h1 className="heading-1 animate-fade-in">Security Dashboard</h1>
          <p className="text-muted animate-fade-in delay-1">
            Autonomous Multi-Agent AI Security Assessment Platform
          </p>
        </header>

        {activeTab === 'dashboard' && (
          <div>
            {/* Scan Form */}
            <ScanForm onScanStart={handleScanStart} isScanning={isScanning} />

            {/* Error Banner */}
            {scanError && (
              <div
                className="glass-card animate-fade-in"
                style={{
                  borderLeft: '4px solid var(--error)',
                  color: 'var(--error)',
                  marginBottom: '1.5rem',
                  padding: '1rem 1.5rem',
                }}
              >
                <strong>Error:</strong> {scanError}
              </div>
            )}

            {/* Agent Pipeline (while scanning or done) */}
            {(isScanning || scanResult) && scanStatus && (
              <AgentProgress status={scanStatus} />
            )}

            {/* Live Results */}
            {scanResult && <LiveResultsPanel data={scanResult} />}

            {/* Empty state (before any scan) */}
            {!isScanning && !scanResult && !scanError && (
              <div
                className="glass-panel animate-fade-in"
                style={{ padding: '4rem 2rem', textAlign: 'center' }}
              >
                <ShieldAlert
                  size={56}
                  color="var(--text-secondary)"
                  style={{ margin: '0 auto 1rem', opacity: 0.3 }}
                />
                <h2 className="heading-2">No Assessment Running</h2>
                <p className="text-muted">
                  Enter a target URL above to launch a full autonomous security assessment.
                </p>
              </div>
            )}
          </div>
        )}

        {activeTab === 'agents' && <AgentsPanel currentScanStatus={scanStatus} />}

        {activeTab === 'reports' && <ScanHistory />}

        {activeTab === 'settings' && <SettingsPanel />}
      </main>

      <style>{`
        @keyframes spin {
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
