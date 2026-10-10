import '@testing-library/jest-dom'
import { vi } from 'vitest'
import React from 'react'

// Mock ALL lucide-react icons as simple spans
// This avoids needing to enumerate icons in each test file
vi.mock('lucide-react', async (importOriginal) => {
  const actual = await importOriginal()
  const MockIcon = (name) => (props) => React.createElement('span', {
    'data-testid': 'mock-icon',
    'data-icon-name': name,
    ...props,
  }, name)
  const result = {}
  for (const key of Object.keys(actual)) {
    if (typeof actual[key] === 'function') {
      result[key] = MockIcon(key)
    } else {
      result[key] = actual[key]
    }
  }
  return result
})

// Mock window.matchMedia
Object.defineProperty(window, 'matchMedia', {
  writable: true,
  value: vi.fn().mockImplementation(query => ({
    matches: false,
    media: query,
    onchange: null,
    addListener: vi.fn(),
    removeListener: vi.fn(),
    addEventListener: vi.fn(),
    removeEventListener: vi.fn(),
    dispatchEvent: vi.fn(),
  })),
})

// Mock window.URL.createObjectURL for download tests
URL.createObjectURL = vi.fn(() => 'blob:mock-url')
URL.revokeObjectURL = vi.fn()

// Mock clipboard API
Object.assign(navigator, {
  clipboard: {
    writeText: vi.fn().mockResolvedValue(undefined),
  },
})
