/**
 * Application shell tests (Phase 7B frontend testing).
 */
import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import App from '../App'
import { renderWithProviders } from '../__tests__/testHelpers'

const { mockGetDashboardStats, mockGetToolsStatus, mockGetAiStatus, mockListAllScans } = vi.hoisted(() => ({
  mockGetDashboardStats: vi.fn(),
  mockGetToolsStatus: vi.fn(),
  mockGetAiStatus: vi.fn(),
  mockListAllScans: vi.fn(),
}))

vi.mock('../services/api.js', () => ({
  checkHealth: vi.fn().mockResolvedValue({ status: 'ok', port: 8000 }),
  getApiKey: vi.fn().mockReturnValue('test-key'),
  getDashboardStats: mockGetDashboardStats,
  getToolsStatus: mockGetToolsStatus,
  getAiStatus: mockGetAiStatus,
  listAllScans: mockListAllScans,
}))
// Mock lazy-loaded pages with unique content test IDs
vi.mock('../context/AppContext.jsx', () => ({
  useApp: () => ({ backendReachable: true, checkBackend: vi.fn(), apiKey: 'test-key' }),
  AppProviders: ({ children }) => React.createElement(React.Fragment, null, children),
}))
vi.mock('../pages/DashboardPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'dashboard-page' }) }))
vi.mock('../pages/NewAssessmentPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'new-assessment-page' }) }))
vi.mock('../pages/ScanHistoryPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'scan-history-page' }) }))
vi.mock('../pages/ScanDetailPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'scan-detail-page' }) }))
vi.mock('../pages/FindingsPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'findings-page' }) }))
vi.mock('../pages/FindingDetailPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'finding-detail-page' }) }))
vi.mock('../pages/ToolsPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'tools-page' }) }))
vi.mock('../pages/AgentsPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'agents-page' }) }))
vi.mock('../pages/ReportsPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'reports-page' }) }))
vi.mock('../pages/SettingsPage.jsx', () => ({ default: () => React.createElement('div', { 'data-testid': 'settings-page' }) }))

describe('Application', () => {
  beforeEach(() => {
    mockGetDashboardStats.mockResolvedValue({
      total_scans: 5,
      by_status: { COMPLETED: 3, RUNNING: 2 },
      findings_by_severity: { CRITICAL: 2, HIGH: 5, MEDIUM: 3, LOW: 1, INFO: 4 },
      open_triage_count: 7,
      recent_scans: [{ scan_id: 'scan-001', target_url: 'http://localhost:5000', status: 'COMPLETED', overall_score: 75, created_at: '2024-01-01T12:00:00Z' }],
    })
    mockGetToolsStatus.mockResolvedValue({ tools: [] })
    mockGetAiStatus.mockResolvedValue({ ai_ready: false, model: 'mock' })
    mockListAllScans.mockResolvedValue([])
  })
  afterEach(() => vi.clearAllMocks())

  test('app renders without crashing', () => {
    renderWithProviders(<App />)
    expect(screen.getByText(/CyberPilot/i)).toBeInTheDocument()
  })

  test('router loads and application shell renders', async () => {
    renderWithProviders(<App />)
    await waitFor(() => { expect(screen.getByRole('navigation')).toBeInTheDocument() })
  })

  test('sidebar navigation renders with all items', async () => {
    renderWithProviders(<App />)
    // Use getAllByText since nav items may have matching text elsewhere
    await waitFor(() => { expect(screen.getAllByText('Dashboard').length).toBeGreaterThan(0) })
    expect(screen.getAllByText('New Assessment').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Scan History').length).toBeGreaterThan(0)
    expect(screen.getAllByText('All Findings').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Agents').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Tools').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Reports').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Settings').length).toBeGreaterThan(0)
  })

  test('branding renders in sidebar', () => {
    renderWithProviders(<App />)
    expect(screen.getByText('CyberPilot')).toBeInTheDocument()
  })

  test('main content area renders', async () => {
    renderWithProviders(<App />)
    await waitFor(() => { expect(screen.getByRole('main')).toBeInTheDocument() })
  })
})
