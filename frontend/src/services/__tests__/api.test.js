/**
 * apiFetch auto-recovery tests (Phase 7B).
 *
 * Tests covering:
 *  - Valid API key does not trigger recovery (no /setup call)
 *  - Invalid/revoked key triggers exactly one recovery attempt via /setup
 *  - Original request is retried no more than once
 *  - Persistent 401 (recovery fails) does not create an infinite retry loop
 *  - Concurrent 401 responses share a single /setup call (deduplication)
 *  - Non-authentication errors (e.g., 500) do not trigger recovery
 *  - API keys are never written to logs
 */
import { vi, describe, it, expect, beforeEach, afterEach } from 'vitest'

// Import the REAL api.js — no mocks. We mock global fetch and localStorage.
import { apiFetch, listApiKeys, _resetRecoveryState } from '../api'

describe('apiFetch auto-recovery', () => {
  let fetchMock
  let store

  beforeEach(() => {
    _resetRecoveryState()

    // Mock localStorage via vi.stubGlobal (jsdom makes global.localStorage read-only)
    store = {}
    vi.stubGlobal('localStorage', {
      getItem: vi.fn((key) => store[key] || null),
      setItem: vi.fn((key, val) => { store[key] = val }),
      removeItem: vi.fn((key) => { delete store[key] }),
      clear: vi.fn(() => { Object.keys(store).forEach(k => delete store[k]) }),
    })

    // Mock fetch
    fetchMock = vi.fn()
    global.fetch = fetchMock
  })

  afterEach(() => {
    vi.unstubAllGlobals()
  })

  it('valid key does not trigger recovery (no /setup call)', async () => {
    store['cyberpilot_api_key'] = 'cpk_valid_key_1234567890ab'

    fetchMock.mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ keys: [{ id: 1, name: 'primary' }] }),
    })

    const res = await apiFetch('http://localhost:8000/api/v1/auth/keys')
    const data = await res.json()

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(data.keys).toHaveLength(1)
  })

  it('invalid key triggers exactly one recovery attempt via /setup', async () => {
    store['cyberpilot_api_key'] = 'cpk_stale_invalid_key_12345'

    // 1st call (original request with stale key) -> 401
    // 2nd call (/setup recovery) -> 200 with new key
    // 3rd call (retry original request with new key) -> 200
    fetchMock
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ detail: 'Invalid or revoked API key' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ key: 'cpk_new_recovered_key_1234567890', name: 'auto-recovery' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ([{ id: 1, name: 'recovered' }]),
      })

    const res = await apiFetch('http://localhost:8000/api/v1/auth/keys')
    const data = await res.json()

    expect(fetchMock).toHaveBeenCalledTimes(3) // original + /setup + retry
    expect(data).toHaveLength(1)
    // /setup was called (2nd call)
    const setupCall = fetchMock.mock.calls[1]
    expect(setupCall[0]).toContain('/setup')
    expect(setupCall[1].method).toBe('POST')
    // New key was saved to localStorage
    expect(store['cyberpilot_api_key']).toBe('cpk_new_recovered_key_1234567890')
  })

  it('original request retried no more than once', async () => {
    store['cyberpilot_api_key'] = 'cpk_stale_key_12345'

    // 401 -> /setup succeeds -> retry -> also 401 (persistent failure)
    fetchMock
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ detail: 'Invalid or revoked API key' }),
      })
      .mockResolvedValueOnce({
        ok: true,
        status: 200,
        json: async () => ({ key: 'cpk_newkey_1234567890ab', name: 'auto-recovery' }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ detail: 'Invalid or revoked API key' }),
      })

    const res = await apiFetch('http://localhost:8000/api/v1/auth/keys')

    // 3 calls: original, /setup, retry. No 4th call.
    expect(fetchMock).toHaveBeenCalledTimes(3)
    expect(res.status).toBe(401)
  })

  it('persistent 401 does not create an infinite retry loop', async () => {
    store['cyberpilot_api_key'] = 'cpk_stale_key_12345'

    // /setup itself returns 401 (edge case, but test it)
    fetchMock.mockResolvedValue({
      ok: false,
      status: 401,
      json: async () => ({ detail: 'Unauthorized' }),
    })

    const res = await apiFetch('http://localhost:8000/api/v1/auth/keys')

    // 2 calls: original + /setup. No retry.
    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(res.status).toBe(401)
  })

  it('concurrent 401 responses share a single /setup call', async () => {
    store['cyberpilot_api_key'] = 'cpk_stale_key_12345'

    let callCount = 0
    fetchMock.mockImplementation(async (url) => {
      callCount++
      if (url.includes('/setup')) {
        return {
          ok: true,
          status: 200,
          json: async () => ({ key: 'cpk_concurrent_new_key_12345', name: 'auto-recovery' }),
        }
      }
      if (callCount <= 2) {
        return {
          ok: false,
          status: 401,
          json: async () => ({ detail: 'Invalid or revoked API key' }),
        }
      }
      return {
        ok: true,
        status: 200,
        json: async () => ([{ id: 1, name: 'key' }]),
      }
    })

    const [res1, res2] = await Promise.all([
      apiFetch('http://localhost:8000/api/v1/auth/keys'),
      apiFetch('http://localhost:8000/api/v1/auth/keys'),
    ])

    // Only ONE /setup call for concurrent 401s
    const setupCalls = fetchMock.mock.calls.filter(c => c[0].includes('/setup'))
    expect(setupCalls).toHaveLength(1)

    expect(res1.ok).toBe(true)
    expect(res2.ok).toBe(true)
  })

  it('non-auth errors (500) do not trigger recovery', async () => {
    store['cyberpilot_api_key'] = 'cpk_valid_key_12345'

    fetchMock.mockResolvedValue({
      ok: false,
      status: 500,
      json: async () => ({ detail: 'Internal server error' }),
    })

    const res = await apiFetch('http://localhost:8000/api/v1/auth/keys')

    expect(fetchMock).toHaveBeenCalledTimes(1)
    expect(res.status).toBe(500)
  })

  it('recovery failure produces a response with 401 status', async () => {
    store['cyberpilot_api_key'] = 'cpk_stale_key_12345'

    fetchMock
      .mockResolvedValueOnce({
        ok: false,
        status: 401,
        json: async () => ({ detail: 'Invalid or revoked API key' }),
      })
      .mockResolvedValueOnce({
        ok: false,
        status: 503,
        json: async () => ({ detail: 'Service unavailable' }),
      })

    const res = await apiFetch('http://localhost:8000/api/v1/auth/keys')

    expect(fetchMock).toHaveBeenCalledTimes(2)
    expect(res.status).toBe(401)
  })

  it('API key is not written to console.log', async () => {
    store['cyberpilot_api_key'] = 'cpk_stale_key_12345'
    const consoleSpy = vi.spyOn(console, 'log')

    fetchMock
      .mockResolvedValueOnce({ ok: false, status: 401, json: async () => ({ detail: 'Invalid' }) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => ({ key: 'cpk_super_secret_key_123!', name: 'auto-recovery' }) })
      .mockResolvedValueOnce({ ok: true, status: 200, json: async () => [] })

    await apiFetch('http://localhost:8000/api/v1/auth/keys')

    const loggedTexts = consoleSpy.mock.calls.map(args => args.map(a => String(a)).join(' '))
    const leaked = loggedTexts.find(text => text.includes('cpk_super_secret_key_123!'))
    expect(leaked).toBeUndefined()
    consoleSpy.mockRestore()
  })

  it('listApiKeys succeeds after auto-recovery', async () => {
    store['cyberpilot_api_key'] = 'cpk_stale_key_12345'

    fetchMock
      .mockResolvedValueOnce({
        ok: false, status: 401,
        json: async () => ({ detail: 'Invalid or revoked API key' }),
      })
      .mockResolvedValueOnce({
        ok: true, status: 200,
        json: async () => ({ key: 'cpk_new_key_1234567890ab', name: 'auto-recovery' }),
      })
      .mockResolvedValueOnce({
        ok: true, status: 200,
        json: async () =>([{ id: 1, name: 'recovered', key_prefix: 'cpk_new_', created_at: '2024-01-01', is_active: true }]),
      })

    const keys = await listApiKeys()
    expect(keys).toHaveLength(1)
    expect(keys[0].name).toBe('recovered')
  })
})
