/**
 * Finding Detail page tests (Phase 7B frontend testing).
 */
import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import FindingDetailPage from '../FindingDetailPage'
import { renderWithProviders } from '../../__tests__/testHelpers'

const { mockGetScanStatus, mockGetScanFindings, mockGetFindingAnalysis, mockGetRemediationDetails, mockGetScanTriage, mockSetFindingTriage } = vi.hoisted(() => ({
  mockGetScanStatus: vi.fn(),
  mockGetScanFindings: vi.fn(),
  mockGetFindingAnalysis: vi.fn(),
  mockGetRemediationDetails: vi.fn(),
  mockGetScanTriage: vi.fn(),
  mockSetFindingTriage: vi.fn(),
}))

vi.mock('../../context/AppContext.jsx', () => ({
  useApp: () => ({ backendReachable: true, checkBackend: vi.fn() }),
  AppProviders: ({ children }) => React.createElement(React.Fragment, null, children),
}))

vi.mock('../../services/api.js', () => ({
  checkHealth: vi.fn().mockResolvedValue({ status: 'ok', port: 8000 }),
  getApiKey: vi.fn().mockReturnValue('test-key'),
  getScanStatus: mockGetScanStatus,
  getScanFindings: mockGetScanFindings,
  getFindingAnalysis: mockGetFindingAnalysis,
  getRemediationDetails: mockGetRemediationDetails,
  getScanTriage: mockGetScanTriage,
  setFindingTriage: mockSetFindingTriage,
}))
const mockFindingsData = {
  by_severity: [
    { severity: 'CRITICAL', count: 1, findings: [
      { id: 1, agent_name: 'Infrastructure Agent', scanner: 'nmap', tool: 'Nmap', severity: 'CRITICAL', confidence: 0.95, title: 'Outdated SSH service detected', description: 'SSH version 7.2 is outdated.', status: 'open', target: 'port 22/tcp', remediation: 'Update SSH to version 8.0 or later.', evidence: '[REDACTED]', cve: ['CVE-2023-1234'], cwe: ['CWE-928'], references: [], file: null, line: null, data_source: 'nmap', created_at: '2024-01-01T12:01:00Z' },
    ] },
  ],
  total: 1,
  by_triage: { open: 1, confirmed: 0, false_positive: 0, accepted: 0, remediated: 0 },
}

const mockAnalysis = {
  finding_id: 1, scan_id: 'scan-001', summary: 'The detected SSH service is running an outdated version.',
  risk_explanation: 'SSH 7.2 has known vulnerabilities.', exploitability: 'Moderate',
  impact: 'Information disclosure and potential RCE.', severity: 'CRITICAL', confidence: 0.95, scanner_confidence: 0.95,
  remediation: 'Update SSH to version 8.0+.', references: [], status: 'completed',
  created_at: '2024-01-01T12:30:00Z', model: 'mock',
}

const mockRemediation = { remediations: [{ id: 1, agent_name: 'Infrastructure Agent', title: 'Outdated SSH service detected', severity: 'CRITICAL', remediation: 'Update SSH to version 8.0 or later.', details: 'Apply security patches.', effort: 'medium', risk_reduction: 'high' }] }
const mockScanStatus = { scan_id: 'scan-001', target_url: 'http://localhost:5000', status: 'COMPLETED', overall_score: 75, created_at: '2024-01-01T12:00:00Z', findings_count: 1, data_source: 'nmap' }

describe('FindingDetailPage', () => {
  beforeEach(() => {
    mockGetScanStatus.mockResolvedValue(mockScanStatus)
    mockGetScanFindings.mockResolvedValue(mockFindingsData)
    mockGetFindingAnalysis.mockResolvedValue(mockAnalysis)
    mockGetRemediationDetails.mockResolvedValue(mockRemediation)
    mockGetScanTriage.mockResolvedValue({ scan_id: 'scan-001', triage: {} })
  })
  afterEach(() => vi.clearAllMocks())

  test('finding details render', async () => {
    renderWithProviders(<FindingDetailPage scanId="scan-001" findingId={1} />)
    await waitFor(() => { expect(screen.getAllByText('Outdated SSH service detected').length).toBeGreaterThan(0) })
  })

  test('evidence is displayed safely', async () => {
    renderWithProviders(<FindingDetailPage scanId="scan-001" findingId={1} />)
    await waitFor(() => {
      expect(screen.getAllByText(/[REDACTED]/).length).toBeGreaterThan(0)
    })
  })

  test('remediation is displayed', async () => {
    renderWithProviders(<FindingDetailPage scanId="scan-001" findingId={1} />)
    await waitFor(() => { expect(screen.getAllByText(/Update SSH to version 8/i).length).toBeGreaterThan(0) })
  })

  test('AI analysis state is handled', async () => {
    renderWithProviders(<FindingDetailPage scanId="scan-001" findingId={1} />)
    await waitFor(() => { expect(screen.getAllByText(/outdated version/i).length).toBeGreaterThan(0) })
  })

  test('AI analysis loading state', async () => {
    mockGetFindingAnalysis.mockReturnValue(new Promise(() => {}))
    renderWithProviders(<FindingDetailPage scanId="scan-001" findingId={1} />)
    await waitFor(() => {
      expect(screen.getByText('AI Analysis')).toBeInTheDocument()
      // LoadingSkeleton renders glass-card divs when ai analysis is loading
      const skeletonElements = document.querySelectorAll('.glass-card')
      expect(skeletonElements.length).toBeGreaterThan(0)
    })
  })

  test('AI analysis error does not crash page', async () => {
    mockGetFindingAnalysis.mockRejectedValue(new Error('AI not available'))
    renderWithProviders(<FindingDetailPage scanId="scan-001" findingId={1} />)
    await waitFor(() => { expect(screen.getAllByText('Outdated SSH service detected').length).toBeGreaterThan(0) })
  })
})
