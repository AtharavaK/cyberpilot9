import React, { createContext, useContext, useState, useCallback, useEffect } from 'react';
import { checkHealth, getApiKey } from '../services/api.js';

const AppContext = createContext();

export const useApp = () => {
  const ctx = useContext(AppContext);
  if (!ctx) throw new Error('useApp must be used within AppProvider');
  return ctx;
};

export const AppProvider = ({ children }) => {
  const [apiKey, setApiKey] = useState(() => getApiKey() || '');
  const [backendReachable, setBackendReachable] = useState(true);
  const [healthChecked, setHealthChecked] = useState(false);

  const checkBackend = useCallback(async () => {
    setHealthChecked(true);
    try {
      await checkHealth();
      setBackendReachable(true);
    } catch {
      setBackendReachable(false);
    }
  }, []);

  useEffect(() => {
    checkBackend();
  }, [checkBackend]);

  const value = {
    apiKey,
    setApiKey,
    backendReachable,
    healthChecked,
    checkBackend,
  };

  return <AppContext.Provider value={value}>{children}</AppContext.Provider>;
};
