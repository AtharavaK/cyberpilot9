/**
 * Tools page tests (Phase 7B frontend testing).
 */
import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'
import ToolsPage from '../ToolsPage'
import { renderWithProviders } from '../../__tests__/testHelpers'

const { mockGetToolsStatus, mockGetAiStatus } = vi.hoisted(() => ({
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
  getToolsStatus: mockGetToolsStatus,
  getAiStatus: mockGetAiStatus,
}))
const mockTools = { tools: [
  { name: 'Nmap', tool_name: 'nmap', installed: true, available: true, status: 'ready', version: '7.94', enabled: true },
  { name: 'Gitleaks', tool_name: 'gitleaks', installed: true, available: true, status: 'ready', version: '8.30.1', enabled: true },
  { name: 'OWASP ZAP', tool_name: 'zap', installed: true, available: true, status: 'ready', version: '2.16.0', enabled: true },
  { name: 'Trivy', tool_name: 'trivy', installed: true, available: true, status: 'ready', version: '0.75.0', enabled: true },
] }
const mockAi = { ai_ready: false, model: 'mock' }

describe('ToolsPage', () => {
  beforeEach(() => {
    mockGetToolsStatus.mockResolvedValue(mockTools)
    mockGetAiStatus.mockResolvedValue(mockAi)
  })
  afterEach(() => vi.clearAllMocks())

  test('tool status renders', async () => {
    renderWithProviders(<ToolsPage />)
    await waitFor(() => { expect(screen.getByText('Tools')).toBeInTheDocument() })
    expect(screen.getAllByText('Nmap').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Gitleaks').length).toBeGreaterThan(0)
    expect(screen.getAllByText('OWASP ZAP').length).toBeGreaterThan(0)
    expect(screen.getAllByText('Trivy').length).toBeGreaterThan(0)
  })

  test('unavailable tools are represented correctly', async () => {
    mockGetToolsStatus.mockResolvedValue({ tools: [
      { name: 'Nmap', installed: true, available: true, status: 'ready', version: '7.94' },
      { name: 'Trivy', installed: false, available: false, status: 'not_installed', version: null },
    ] })
    renderWithProviders(<ToolsPage />)
    await waitFor(() => { expect(screen.getAllByText('Not Installed').length).toBeGreaterThan(0) })
  })

  test('loading state', () => {
    mockGetToolsStatus.mockReturnValue(new Promise(() => {}))
    renderWithProviders(<ToolsPage />)
    expect(screen.getByText('Tools')).toBeInTheDocument()
  })

  test('error state', async () => {
    mockGetToolsStatus.mockRejectedValue(new Error('Connection failed'))
    renderWithProviders(<ToolsPage />)
    await waitFor(() => { expect(screen.getByText(/Connection failed/i)).toBeInTheDocument() })
  })

  test('installation guide section renders', async () => {
    renderWithProviders(<ToolsPage />)
    await waitFor(() => { expect(screen.getByText('Installation Guide')).toBeInTheDocument() })
  })
})
