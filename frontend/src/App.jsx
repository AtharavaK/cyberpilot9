import React from 'react';
import { Routes, Route, Navigate } from 'react-router-dom';
import ApplicationShell from './components/ApplicationShell.jsx';
import DashboardPage from './pages/DashboardPage.jsx';
import NewAssessmentPage from './pages/NewAssessmentPage.jsx';
import ScanHistoryPage from './pages/ScanHistoryPage.jsx';
import ScanDetailPage from './pages/ScanDetailPage.jsx';
import FindingsPage from './pages/FindingsPage.jsx';
import FindingDetailPage from './pages/FindingDetailPage.jsx';
import ToolsPage from './pages/ToolsPage.jsx';
import AgentsPage from './pages/AgentsPage.jsx';
import ReportsPage from './pages/ReportsPage.jsx';
import SettingsPage from './pages/SettingsPage.jsx';
import ErrorBoundary from './components/ErrorBoundary.jsx';

export default function App() {
  return (
    <ErrorBoundary>
      <Routes>
      <Route path="/" element={<ApplicationShell />}>
        <Route index element={<DashboardPage />} />
          <Route path="dashboard" element={<Navigate to="/" replace />} />
          <Route path="new" element={<NewAssessmentPage />} />
          <Route path="scans" element={<ScanHistoryPage />} />
          <Route path="scans/:scanId" element={<ScanDetailPage />} />
          <Route path="findings" element={<FindingsPage />} />
          <Route path="findings/:findingId" element={<FindingDetailPage />} />
          <Route path="tools" element={<ToolsPage />} />
          <Route path="agents" element={<AgentsPage />} />
          <Route path="reports" element={<ReportsPage />} />
          <Route path="settings" element={<SettingsPage />} />
        </Route>
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </ErrorBoundary>
  );
}
