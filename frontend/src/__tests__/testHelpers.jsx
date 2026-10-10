/**
 * Shared test helpers for CyberPilot frontend tests.
 * Provides render utilities that wrap components with BrowserRouter.
 */
import React from 'react'
import { render } from '@testing-library/react'
import { BrowserRouter } from 'react-router-dom'

// renderWithProviders wraps with BrowserRouter only.
// AppContext is mocked by each test file for useApp() access.
export function renderWithProviders(ui) {
  return render(
    <BrowserRouter>
      {ui}
    </BrowserRouter>
  )
}
