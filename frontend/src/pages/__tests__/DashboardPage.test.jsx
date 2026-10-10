/**
 * Dashboard page tests (Phase 7B frontend testing).
 */
import React from 'react'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { vi } from 'vitest'
import DashboardPage from '../DashboardPage'
import { renderWithProviders } from '../../__tests__/testHelpers'

const { mockGetDashboardStats, mockGetToolsStatus, mockGetAiStatus } = vi.hoisted(() => ({
  mockGetDashboardStats: vi.fn(),
  mockGetToolsStatus: vi.fn(),
  mockGetAiStatus: vi.fn(),
}))

vi.mock('../../context/AppContext.jsx', () => ({
  useApp: () => ({ backendReachable: true, checkBackend: vi.fn() }),
  AppProviders: ({ children }) => React.createElement(React.Fragment, null, children),
}))

vi.mock('../../services/api.js', () => ({
  checkHealth: vi.fn().mockResolvedValue({ status: 'ok', port: 8000 }),
  getApiKey: vi.fn().mockReturnValue('test-key'),
  getDashboardStats: mockGetDashboardStats,
  getToolsStatus: mockGetToolsStatus,
  getAiStatus: mockGetAiStatus,
}))
const mockStats = {
  total_scans: 5,
  by_status: { COMPLETED: 3, RUNNING: 2 },
  findings_by_severity: { CRITICAL: 2, HIGH: 5, MEDIUM: 3, LOW: 1, INFO: 4 },
  open_triage_count: 7,
  recent_scans: [
    { scan_id: 'scan-001', target_url: 'http://localhost:5000', status: 'COMPLETED', overall_score: 75, created_at: '2024-01-01T12:00:00Z' },
  ],
}
const mockTools = { tools: [
  { name: 'Nmap', installed: true, available: true, status: 'ready', version: '7.94' },
  { name: 'Trivy', installed: true, available: true, status: 'ready', version: '0.75.0' },
  { name: 'AI Engine (Ollama)', installed: false, available: false, status: 'not_installed', version: null, enabled: false },
] }
const mockAi = { ai_ready: false, model: 'mock' }

describe('DashboardPage', () => {
  beforeEach(() => {
    mockGetDashboardStats.mockResolvedValue(mockStats)
    mockGetToolsStatus.mockResolvedValue(mockTools)
    mockGetAiStatus.mockResolvedValue(mockAi)
  })
  afterEach(() => vi.clearAllMocks())

  test('dashboard renders', async () => {
    renderWithProviders(<DashboardPage />)
    await waitFor(() => { expect(screen.getByText('Dashboard')).toBeInTheDocument() })
  })

  test('loading state shows when data is pending', () => {
    mockGetDashboardStats.mockReturnValue(new Promise(() => {}))
    renderWithProviders(<DashboardPage />)
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
  })

  test('error state displays', async () => {
    mockGetDashboardStats.mockRejectedValue(new Error('Network error'))
    renderWithProviders(<DashboardPage />)
    await waitFor(() => { expect(screen.getByText(/Network error/i)).toBeInTheDocument() })
  })

  test('error state has retry button', async () => {
    mockGetDashboardStats.mockRejectedValue(new Error('Failed to load'))
    renderWithProviders(<DashboardPage />)
    await waitFor(() => { expect(screen.getByText('Retry')).toBeInTheDocument() })
  })

  test('empty state when no recent scans', async () => {
    mockGetDashboardStats.mockResolvedValue({ ...mockStats, recent_scans: [] })
    renderWithProviders(<DashboardPage />)
    await waitFor(() => { expect(screen.getByText('No scans yet')).toBeInTheDocument() })
  })

  test('real API data rendering — stats cards', async () => {
    renderWithProviders(<DashboardPage />)
    await waitFor(() => {
      expect(screen.getByText('Total Scans')).toBeInTheDocument()
      expect(screen.getByText('Active Scans')).toBeInTheDocument()
      expect(screen.getByText('Completed')).toBeInTheDocument()
      expect(screen.getByText('Findings (Open)')).toBeInTheDocument()
      expect(screen.getByText('Triage Needed')).toBeInTheDocument()
      expect(screen.getByText('AI Status')).toBeInTheDocument()
    })
  })

  test('real API data rendering — scan counts', async () => {
    renderWithProviders(<DashboardPage />)
    await waitFor(() => {
      const totalCard = screen.getByText('Total Scans').closest('.stat-card')
      expect(totalCard.textContent).toContain('5')
      const completedCard = screen.getByText('Completed').closest('.stat-card')
      expect(completedCard.textContent).toContain('3')
    })
  })

  test('real API data rendering — severity labels', async () => {
    renderWithProviders(<DashboardPage />)
    await waitFor(() => {
      expect(screen.getAllByText('Critical').length).toBeGreaterThan(0)
      expect(screen.getAllByText('High').length).toBeGreaterThan(0)
      expect(screen.getAllByText('Medium').length).toBeGreaterThan(0)
      expect(screen.getAllByText('Low').length).toBeGreaterThan(0)
    })
  })

  test('real API data rendering — tool status', async () => {
    renderWithProviders(<DashboardPage />)
    await waitFor(() => {
      expect(screen.getAllByText('Nmap').length).toBeGreaterThan(0)
      expect(screen.getAllByText('Trivy').length).toBeGreaterThan(0)
    })
  })

  test('real API data rendering — AI status shows unavailable', async () => {
    renderWithProviders(<DashboardPage />)
    await waitFor(() => { expect(screen.getAllByText('Unavailable').length).toBeGreaterThan(0) })
  })

  test('recent scans appear in dashboard', async () => {
    renderWithProviders(<DashboardPage />)
    await waitFor(() => { expect(screen.getAllByText('http://localhost:5000').length).toBeGreaterThan(0) })
  })

  test('refresh button triggers reload', async () => {
    renderWithProviders(<DashboardPage />)
    await waitFor(() => { expect(screen.getByText('Refresh')).toBeInTheDocument() })
    fireEvent.click(screen.getByText('Refresh'))
    await waitFor(() => { expect(mockGetDashboardStats).toHaveBeenCalledTimes(2) })
  })
})
