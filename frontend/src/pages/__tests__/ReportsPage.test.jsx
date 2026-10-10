/**
 * Reports page tests (Phase 7B frontend testing).
 */
import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import ReportsPage from '../ReportsPage'
import { renderWithProviders } from '../../__tests__/testHelpers'

const { mockListAllScans, mockDownloadExecutiveSummary, mockDownloadTechnicalReport } = vi.hoisted(() => ({
  mockListAllScans: vi.fn(),
  mockDownloadExecutiveSummary: vi.fn(),
  mockDownloadTechnicalReport: vi.fn(),
}))

vi.mock('../../context/AppContext.jsx', () => ({
  useApp: () => ({ backendReachable: true, checkBackend: vi.fn() }),
  AppProviders: ({ children }) => React.createElement(React.Fragment, null, children),
}))

vi.mock('../../services/api.js', () => ({
  checkHealth: vi.fn().mockResolvedValue({ status: 'ok', port: 8000 }),
  getApiKey: vi.fn().mockReturnValue('test-key'),
  listAllScans: mockListAllScans,
  downloadExecutiveSummary: mockDownloadExecutiveSummary,
  downloadTechnicalReport: mockDownloadTechnicalReport,
}))
const mockScansList = [
  { scan_id: 'scan-001', target_url: 'http://localhost:5000', status: 'COMPLETED', overall_score: 75, created_at: '2024-01-01T12:00:00Z', findings_count: 13, data_source: 'nmap,gitleaks,zap' },
  { scan_id: 'scan-002', target_url: 'http://localhost:3000', status: 'RUNNING', overall_score: null, created_at: '2024-01-02T10:00:00Z', findings_count: 0, data_source: null },
]

describe('ReportsPage', () => {
  beforeEach(() => {
    mockListAllScans.mockResolvedValue(mockScansList)
    mockDownloadExecutiveSummary.mockResolvedValue(new Blob(['pdf'], { type: 'application/pdf' }))
  })
  afterEach(() => vi.clearAllMocks())

  test('reports page renders', async () => {
    renderWithProviders(<ReportsPage />)
    await waitFor(() => { expect(screen.getByText('Reports')).toBeInTheDocument() })
  })

  test('loading state shows skeletons', () => {
    mockListAllScans.mockReturnValue(new Promise(() => {}))
    renderWithProviders(<ReportsPage />)
    expect(screen.getByText('Reports')).toBeInTheDocument()
  })

  test('empty state works', async () => {
    mockListAllScans.mockResolvedValue([])
    renderWithProviders(<ReportsPage />)
    await waitFor(() => { expect(screen.getByText('No reports available')).toBeInTheDocument() })
  })

  test('completed scans show in reports list', async () => {
    renderWithProviders(<ReportsPage />)
    await waitFor(() => { expect(screen.getAllByText('Executive Summary (PDF)').length).toBeGreaterThan(0) })
    expect(screen.getAllByText('Technical Report (PDF)').length).toBeGreaterThan(0)
  })

  test('only completed scans shown', async () => {
    renderWithProviders(<ReportsPage />)
    await waitFor(() => { expect(screen.getAllByText('http://localhost:5000').length).toBeGreaterThan(0) })
    expect(screen.queryByText('http://localhost:3000')).not.toBeInTheDocument()
  })
})
