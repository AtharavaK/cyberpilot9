import React from 'react';
import { useLocation, useNavigate, Outlet } from 'react-router-dom';
import {
  ShieldAlert, LayoutDashboard, Plus, FileText, Bot, Settings,
  Activity, Search, Target, Users, Wrench, BarChart3, X,
} from 'lucide-react';
import { useApp } from '../context/AppContext.jsx';
import { StatusIndicator } from './ui.jsx';

const NAV_ITEMS = [
  { key: '/', label: 'Dashboard', icon: LayoutDashboard },
  { key: '/new', label: 'New Assessment', icon: Plus },
  { key: '/scans', label: 'Scan History', icon: FileText },
  { key: '/findings', label: 'All Findings', icon: Search },
  { key: '/agents', label: 'Agents', icon: Bot },
  { key: '/tools', label: 'Tools', icon: Wrench },
  { key: '/reports', label: 'Reports', icon: BarChart3 },
  { key: '/settings', label: 'Settings', icon: Settings },
];

export default function ApplicationShell() {
  const location = useLocation();
  const navigate = useNavigate();
  const { backendReachable, checkBackend } = useApp();

  const activePath = location.pathname;

  return (
    <div className="app-container">
      {/* Sidebar */}
      <aside className="sidebar">
        <div className="brand">
          <ShieldAlert size={28} color="var(--accent-primary)" />
          CyberPilot
        </div>

        <nav>
          {NAV_ITEMS.map(({ key, label, icon: Icon }) => {
            const isActive = activePath === key || activePath.startsWith(key + '/');
            return (
              <div
                key={key}
                className={`nav-item ${isActive ? 'active' : ''}`}
                onClick={() => navigate(key)}
                role="button"
                tabIndex={0}
                onKeyDown={(e) => { if (e.key === 'Enter' || e.key === ' ') navigate(key); }}
                aria-label={`Navigate to ${label}`}
              >
                <Icon size={20} />
                {label}
              </div>
            );
          })}
        </nav>

        {/* Backend status */}
        <div style={{
          marginTop: 'auto',
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          padding: '0.5rem',
          borderRadius: '8px',
          background: backendReachable ? 'rgba(16,185,129,0.1)' : 'rgba(239,68,68,0.1)',
        }}>
          <StatusIndicator status={backendReachable ? 'ready' : 'unavailable'} />
        </div>
      </aside>

      {/* Main Content */}
      <main className="main-content">
        <Outlet />
      </main>

      <style>{`
        @keyframes spin {
          100% { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}
