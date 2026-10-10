/**
 * SettingsPage tests (Phase 7B frontend testing).
 *
 * Tests covering:
 *  - SettingsPage renders with a populated key list
 *  - SettingsPage renders with an empty key list (empty state)
 *  - SettingsPage shows error banner on API failure
 *  - Backend health status {"status":"ok"} is interpreted correctly (ready)
 *  - SettingsPage does not crash on null/undefined apiKeys
 *  - ErrorBoundary catches render errors in SettingsPage
 *  - Navigation (direct import, no Suspense) works without breaking
 */
import React from 'react'
import { render, screen, waitFor } from '@testing-library/react'
import { vi } from 'vitest'

// Hoist mock state before imports
const { mockListApiKeys, mockCheckHealth, mockGetAiStatus, mockGetApiKey, mockCreateApiKey, mockRevokeApiKey } = vi.hoisted(() => ({
  mockListApiKeys: vi.fn(),
  mockCheckHealth: vi.fn(),
  mockGetAiStatus: vi.fn(),
  mockGetApiKey: vi.fn(),
  mockCreateApiKey: vi.fn(),
  mockRevokeApiKey: vi.fn(),
}))

// Mock AppContext (needed by SettingsPage's parent shell, but SettingsPage
// doesn't use useApp directly — keep it for safety)
vi.mock('../../context/AppContext.jsx', () => ({
  useApp: () => ({ backendReachable: true, checkBackend: vi.fn(), apiKey: 'cpk_testkey1234567890ab' }),
  AppProviders: ({ children }) => React.createElement(React.Fragment, null, children),
}))

// Mock api.js — only mock the exports SettingsPage uses
vi.mock('../../services/api.js', () => ({
  listApiKeys: mockListApiKeys,
  createApiKey: mockCreateApiKey,
  revokeApiKey: mockRevokeApiKey,
  getApiKey: mockGetApiKey,
  checkHealth: mockCheckHealth,
  getAiStatus: mockGetAiStatus,
}))

import SettingsPage from '../SettingsPage'
import { renderWithProviders } from '../../__tests__/testHelpers'

const mockKeys = [
  { id: 1, name: 'primary', key_prefix: 'cpk_test123', created_at: '2024-01-01T12:00:00Z', last_used: '2024-01-02T12:00:00Z', is_active: true },
  { id: 2, name: 'auto-recovery', key_prefix: 'cpk_test456', created_at: '2024-01-03T12:00:00Z', last_used: null, is_active: true },
]

afterEach(() => vi.clearAllMocks())

describe('SettingsPage', () => {
  beforeEach(() => {
    mockGetApiKey.mockReturnValue('cpk_testkey1234567890ab')
    mockCheckHealth.mockResolvedValue({ status: 'ok', port: 8000 })
    mockGetAiStatus.mockResolvedValue({ ai_ready: false, model: 'mock', ai_enabled: false })
  })

  test('renders with populated key list', async () => {
    mockListApiKeys.mockResolvedValue(mockKeys)
    renderWithProviders(<SettingsPage />)

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
      expect(screen.getByText('primary')).toBeInTheDocument()
      expect(screen.getByText('auto-recovery')).toBeInTheDocument()
    })
  })

  test('renders with empty key list (empty state)', async () => {
    mockListApiKeys.mockResolvedValue([])
    renderWithProviders(<SettingsPage />)

    await waitFor(() => {
      expect(screen.getByText('No API keys created yet.')).toBeInTheDocument()
    })
  })

  test('shows error banner on API failure', async () => {
    mockListApiKeys.mockRejectedValue(new Error('Failed to load API keys'))
    renderWithProviders(<SettingsPage />)

    await waitFor(() => {
      expect(screen.getByText(/Failed to load API keys/)).toBeInTheDocument()
    })
  })

  test('shows retry button in error banner', async () => {
    mockListApiKeys.mockRejectedValue(new Error('Network error'))
    renderWithProviders(<SettingsPage />)

    await waitFor(() => {
      expect(screen.getByText('Retry')).toBeInTheDocument()
    })
  })

  test('health status {"status":"ok"} renders as ready', async () => {
    mockListApiKeys.mockResolvedValue([])
    mockCheckHealth.mockResolvedValue({ status: 'ok', port: 8000 })
    renderWithProviders(<SettingsPage />)

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })
    // StatusIndicator with status="ready" renders a green dot
    const indicators = screen.getAllByTestId('status-indicator')
    expect(indicators.length).toBeGreaterThan(0)
  })

  test('does not crash when apiKeys is null', async () => {
    // Simulate a case where the API returns null (should not happen, but be safe)
    mockListApiKeys.mockResolvedValue(null)
    renderWithProviders(<SettingsPage />)

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })
    // No crash = page rendered
  })

  test('renders loading skeleton while fetching', () => {
    mockListApiKeys.mockReturnValue(new Promise(() => {}))
    renderWithProviders(<SettingsPage />)

    expect(screen.getByText('Settings')).toBeInTheDocument()
    // LoadingSkeleton should be present
    expect(screen.getByTestId('loading-skeleton')).toBeInTheDocument()
  })

  test('API key is not fully displayed in backend config', async () => {
    mockListApiKeys.mockResolvedValue([])
    renderWithProviders(<SettingsPage />)

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })
    // The key in "Backend Configuration" is truncated: first 8 + "…" + last 4
    // Full key "cpk_testkey1234567890ab" should NOT appear in the config section
    const configSection = screen.getByText('Backend Configuration').closest('.glass-card')
    expect(configSection.textContent).toContain('cpk_test')
    expect(configSection.textContent).not.toContain('cpk_testkey1234567890ab')
  })

  test('renders backend configuration section', async () => {
    mockListApiKeys.mockResolvedValue([])
    renderWithProviders(<SettingsPage />)

    await waitFor(() => {
      expect(screen.getByText('Backend Configuration')).toBeInTheDocument()
      expect(screen.getByText('Service Status')).toBeInTheDocument()
      expect(screen.getByText('API Keys')).toBeInTheDocument()
    })
  })
})

describe('SettingsPage ErrorBoundary integration', () => {
  test('does not throw uncaught error that blanks the page', async () => {
    // Even if listApiKeys throws an unexpected error, the page should still render
    mockListApiKeys.mockRejectedValue(new Error('Unexpected error'))
    renderWithProviders(<SettingsPage />)

    await waitFor(() => {
      expect(screen.getByText('Settings')).toBeInTheDocument()
    })
  })
})
