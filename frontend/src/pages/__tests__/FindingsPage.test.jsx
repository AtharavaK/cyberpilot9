/**
 * Findings page tests (Phase 7B frontend testing).
 */
import React from 'react'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { vi } from 'vitest'
import FindingsPage from '../FindingsPage'
import { renderWithProviders } from '../../__tests__/testHelpers'

const mockListAllScans = vi.fn()
const mockGetScanFindings = vi.fn()

vi.mock('../../context/AppContext.jsx', () => ({
  useApp: () => ({ backendReachable: true, checkBackend: vi.fn() }),
  AppProviders: ({ children }) => React.createElement(React.Fragment, null, children),
}))

vi.mock('../../services/api.js', () => ({
  listAllScans: (...args) => mockListAllScans(...args),
  getScanFindings: (...args) => mockGetScanFindings(...args),
  getScanTriage: vi.fn(),
  setFindingTriage: vi.fn(),
  checkHealth: vi.fn().mockResolvedValue({ status: 'ok', port: 8000 }),
  getApiKey: vi.fn().mockReturnValue(''),
}))

const mockScans = [
  { scan_id: 'scan-001', target_url: 'http://localhost:5000', status: 'COMPLETED', overall_score: 75, created_at: '2024-01-01T12:00:00Z', findings_count: 13 },
  { scan_id: 'scan-002', target_url: 'http://localhost:3000', status: 'RUNNING', overall_score: null, created_at: '2024-01-02T10:00:00Z', findings_count: 0 },
]

const mockFindingsData = {
  by_severity: [
    { severity: 'CRITICAL', count: 2, findings: [
      { id: 1, agent_name: 'Infrastructure Agent', scanner: 'nmap', tool: 'Nmap', severity: 'CRITICAL', confidence: 0.95, title: 'Outdated SSH service detected', description: 'SSH version 7.2 is outdated.', status: 'open', target: 'port 22/tcp', remediation: 'Update SSH to version 8.0.', evidence: '[REDACTED]', cve: ['CVE-2023-1234'], cwe: ['CWE-928'], references: [], file: null, line: null, data_source: 'nmap', created_at: '2024-01-01T12:01:00Z' },
      { id: 2, agent_name: 'Infrastructure Agent', scanner: 'gitleaks', tool: 'Gitleaks', severity: 'CRITICAL', confidence: 0.90, title: 'Exposed GitHub PAT', description: 'Secret detected.', status: 'open', target: '.env', remediation: 'Rotate the token.', evidence: '[REDACTED]', cve: [], cwe: ['CWE-798'], references: [], file: '.env', line: 3, data_source: 'gitleaks', created_at: '2024-01-01T12:02:00Z' },
    ] },
    { severity: 'HIGH', count: 1, findings: [
      { id: 3, agent_name: 'Web Application Agent', scanner: 'zap', tool: 'OWASP ZAP', severity: 'HIGH', confidence: 0.85, title: 'Reflected XSS', description: 'XSS in search.', status: 'open', target: 'http://localhost:5000/search', remediation: 'Validate input.', evidence: '[REDACTED]', cve: [], cwe: ['CWE-79'], references: [], file: null, line: null, data_source: 'zap', created_at: '2024-01-01T12:03:00Z' },
    ] },
    { severity: 'MEDIUM', count: 0, findings: [] },
  ],
  total: 3,
  total_findings: 3,
  by_triage: { open: 3, confirmed: 0, false_positive: 0, accepted: 0, remediated: 0 },
}

describe('FindingsPage', () => {
  beforeEach(() => {
    mockListAllScans.mockResolvedValue(mockScans)
    mockGetScanFindings.mockResolvedValue(mockFindingsData)
  })
  afterEach(() => vi.clearAllMocks())

  test('findings render', async () => {
    renderWithProviders(<FindingsPage />)
    await waitFor(() => {
      expect(screen.getAllByText('Outdated SSH service detected').length).toBeGreaterThan(0)
    })
    expect(screen.getAllByText('Exposed GitHub PAT').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Reflected XSS').length).toBeGreaterThan(0)
  })

  test('severity displays correctly', async () => {
    renderWithProviders(<FindingsPage />)
    await waitFor(() => { expect(screen.getAllByText('Critical').length).toBeGreaterThan(0) })
    expect(screen.getAllByText('High').length).toBeGreaterThan(0)
  })

  test('scanner displays correctly', async () => {
    renderWithProviders(<FindingsPage />)
    await waitFor(() => { expect(screen.getAllByText(/Scanner: nmap/).length).toBeGreaterThan(0) })
    expect(screen.getAllByText(/Scanner: gitleaks/).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/Scanner: zap/).length).toBeGreaterThan(0)
  })

  test('empty state works', async () => {
    const emptyFindings = { by_severity: [{ severity: 'CRITICAL', count: 0, findings: [] }], total: 0, total_findings: 0, by_triage: { open: 0 } }
    mockGetScanFindings.mockResolvedValue(emptyFindings)
    renderWithProviders(<FindingsPage />)
    await waitFor(() => { expect(screen.getByText(/No findings match your filters/i)).toBeInTheDocument() })
  })

  test('error state works', async () => {
    mockListAllScans.mockRejectedValue(new Error('Failed to load scans'))
    renderWithProviders(<FindingsPage />)
    await waitFor(() => { expect(screen.getByText(/Failed to load scans/i)).toBeInTheDocument() })
  })
})
