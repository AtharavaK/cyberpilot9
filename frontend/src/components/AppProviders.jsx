import React from 'react';
import { AppProvider } from '../context/AppContext.jsx';

/**
 * Wraps the application with all context providers.
 * This is where additional providers (theme, notifications, etc.) can be added.
 */
export default function AppProviders({ children }) {
  return (
    <AppProvider>
      {children}
    </AppProvider>
  );
}
