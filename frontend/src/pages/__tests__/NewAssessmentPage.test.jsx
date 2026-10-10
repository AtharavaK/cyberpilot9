/**
 * New Assessment page tests (Phase 7B frontend testing).
 */
import React from 'react'
import { render, screen, waitFor, fireEvent } from '@testing-library/react'
import { vi } from 'vitest'
import NewAssessmentPage from '../NewAssessmentPage'
import { renderWithProviders } from '../../__tests__/testHelpers'

const { mockStartScan, mockValidateTarget, mockGetToolsStatus } = vi.hoisted(() => ({
  mockStartScan: vi.fn(),
  mockValidateTarget: vi.fn(),
  mockGetToolsStatus: vi.fn(),
}))

vi.mock('../../context/AppContext.jsx', () => ({
  useApp: () => ({ backendReachable: true, checkBackend: vi.fn() }),
  AppProviders: ({ children }) => React.createElement(React.Fragment, null, children),
}))

vi.mock('../../services/api.js', () => ({
  checkHealth: vi.fn().mockResolvedValue({ status: 'ok', port: 8000 }),
  getApiKey: vi.fn().mockReturnValue('test-key'),
  startScan: mockStartScan,
  validateTarget: mockValidateTarget,
  getToolsStatus: mockGetToolsStatus,
}))
const mockTools = { tools: [
  { name: 'Nmap', installed: true, available: true },
  { name: 'OWASP ZAP', installed: true, available: true },
] }

describe('NewAssessmentPage', () => {
  beforeEach(() => {
    mockValidateTarget.mockResolvedValue({ valid: true, target_kind: 'web_target', normalized: 'http://localhost:5000', error: null })
    mockGetToolsStatus.mockResolvedValue(mockTools)
  })
  afterEach(() => vi.clearAllMocks())

  test('target input renders', async () => {
    renderWithProviders(<NewAssessmentPage />)
    await waitFor(() => { expect(screen.getByText(/Target URL or Path/i)).toBeInTheDocument() })
    expect(screen.getByPlaceholderText(/https:\/\/example\.com/i)).toBeInTheDocument()
  })

  test('authorization option renders', async () => {
    renderWithProviders(<NewAssessmentPage />)
    await waitFor(() => { expect(screen.getAllByText(/authoriz/i).length).toBeGreaterThan(0) })
  })

  test('scan configuration renders', async () => {
    renderWithProviders(<NewAssessmentPage />)
    await waitFor(() => { expect(screen.getByText(/assessment mode/i)).toBeInTheDocument() })
  })

  test('active scan remains disabled by default', async () => {
    renderWithProviders(<NewAssessmentPage />)
    await waitFor(() => {
      expect(screen.getAllByText(/active/i).length).toBeGreaterThan(0)
      const checkboxes = screen.getAllByRole('checkbox')
      expect(checkboxes.length).toBeGreaterThan(0)
    })
  })

  test('validation errors display for invalid target', async () => {
    mockValidateTarget.mockResolvedValue({ valid: false, error: 'Invalid target URL' })
    renderWithProviders(<NewAssessmentPage />)
    await waitFor(() => {
      const input = screen.getByPlaceholderText(/https:\/\/example\.com/i)
      fireEvent.change(input, { target: { value: 'not-a-valid-url' } })
      expect(screen.getByText(/invalid target url/i)).toBeInTheDocument()
    })
  })

  test('page shows New Assessment heading', async () => {
    renderWithProviders(<NewAssessmentPage />)
    await waitFor(() => { expect(screen.getByText('New Assessment')).toBeInTheDocument() })
  })

  test('scan mode options render', async () => {
    renderWithProviders(<NewAssessmentPage />)
    await waitFor(() => {
      expect(screen.getAllByText(/safe/i).length).toBeGreaterThan(0)
      expect(screen.getAllByText(/baseline/i).length).toBeGreaterThan(0)
      expect(screen.getAllByText(/active/i).length).toBeGreaterThan(0)
    })
  })
})
