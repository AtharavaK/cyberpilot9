const DEFAULT_BASE_URL = 'http://localhost:8000/api/v1';

function getBaseUrl() {
  return localStorage.getItem('cyberpilot_api_url') || import.meta.env.VITE_API_URL || DEFAULT_BASE_URL;
}

export function getApiKey() {
  return localStorage.getItem('cyberpilot_api_key') || '';
}

function getHeaders() {
  const headers = { 'Content-Type': 'application/json' };
  const apiKey = getApiKey();
  if (apiKey) {
    headers['Authorization'] = `Bearer ${apiKey}`;
  }
  return headers;
}

// Backend base URL (without /api/v1) for public endpoints like /health and /setup
function getBackendBaseUrl() {
  const base = getBaseUrl();
  return base.replace('/api/v1', '');
}

// ── Auto-recovery: when a 401 is received (invalid/revoked key), create a fresh
// key via the no-auth /setup endpoint and save it to localStorage. ─────────────
// Deduplicates concurrent recovery attempts: if N requests all get 401
// simultaneously, only ONE /setup call is made. The new key is shared
// across all N retries.
let isRefreshing = false;
let refreshPromise = null;

async function recoverApiKey() {
  if (isRefreshing) {
    return refreshPromise;
  }
  isRefreshing = true;
  refreshPromise = (async () => {
    const res = await fetch(`${getBackendBaseUrl()}/setup`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ name: 'auto-recovery' }),
    });
    if (res.ok) {
      const data = await res.json();
      localStorage.setItem('cyberpilot_api_key', data.key);
      return data.key;
    }
    throw new Error('Auto-recovery failed');
  })();
  try {
    return await refreshPromise;
  } finally {
    isRefreshing = false;
    refreshPromise = null;
  }
}

// Central fetch wrapper with 401 auto-recovery.
// - Only HTTP 401 triggers recovery (auth failures: missing/invalid key).
//   All 401 responses from this backend are auth-related (see auth.py).
// - Recovery is attempted at most once per request (retry count = 1).
// - Concurrent 401s share a single recovery attempt (see isRefreshing guard).
// - Non-auth errors (4xx/5xx) never trigger recovery.
// - API keys / bearer tokens are never logged.
async function apiFetch(url, options = {}) {
  const opts = { ...options };
  opts.headers = { ...getHeaders(), ...(options.headers || {}) };
  let res = await fetch(url, opts);

  if (res.status === 401) {
    try {
      const newKey = await recoverApiKey();
      opts.headers['Authorization'] = `Bearer ${newKey}`;
      res = await fetch(url, opts);
    } catch {
      // Auto-recovery failed — return original 401 response
    }
  }

  return res;
}

async function handleResponse(res) {
  if (!res.ok) {
    let errMsg = 'Request failed';
    try {
      const err = await res.json();
      errMsg = err.detail || err.message || errMsg;
    } catch {}
    const error = new Error(errMsg);
    error.status = res.status;
    throw error;
  }
  return res.json();
}

// ── Error handling helper ─────────────────────────────────────────────────────

export function isApiError(err) {
  return err && err.status !== undefined;
}

export function getErrorMessage(err, fallback = 'An unexpected error occurred') {
  if (!err) return fallback;
  if (err.status === 401) return 'Authentication required. Please create an API key in Settings.';
  if (err.status === 403) return 'You are not authorized to perform this action.';
  if (err.status === 404) return 'Resource not found.';
  if (err.status >= 500) return 'The backend service is unavailable. Please check server logs.';
  return err.message || fallback;
}

// ── Scan Management ─────────────────────────────────────────────────────────────

/**
 * Start a new security scan.
 * @param {string} targetUrl
 * @param {boolean} simulate
 * @param {boolean} authorize
 * @param {number} scanTimeoutSeconds
 * @param {object} nmapConfig
 * @returns {Promise<{scan_id: string, status: string, message: string}>}
 */
export async function startScan(targetUrl, simulate = true, authorize = false, scanTimeoutSeconds = 300, nmapConfig = {}) {
  const res = await apiFetch(`${getBaseUrl()}/scan/start`, {
    method: 'POST',
    body: JSON.stringify({
      target_url: targetUrl,
      simulate,
      authorize,
      scan_timeout_seconds: scanTimeoutSeconds,
      nmap_config: nmapConfig,
    }),
  });
  return handleResponse(res);
}

/**
 * Check if a target is valid and get its normalized type.
 * @param {string} targetUrl
 * @returns {Promise<{valid: boolean, target_kind: string, normalized: string, error: string}>}
 */
export async function validateTarget(targetUrl) {
  const res = await apiFetch(`${getBaseUrl()}/scan/validate`, {
    method: 'POST',
    body: JSON.stringify({ target_url: targetUrl }),
  });
  return handleResponse(res);
}

/**
 * Poll the status/result of a scan by its ID.
 * @param {string} scanId
 * @returns {Promise<object>}
 */
export async function getScanStatus(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/status`);
  return handleResponse(res);
}

/**
 * Get scan events (live activity log).
 * @param {string} scanId
 * @param {number} sinceId
 * @returns {Promise<{scan_id: string, events: Array, latest_event: object|null}>}
 */
export async function getScanEvents(scanId, sinceId = 0) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/events?since_id=${sinceId}`);
  return handleResponse(res);
}

/**
 * Get findings for a scan (grouped explorer).
 * @param {string} scanId
 * @returns {Promise<object>}
 */
export async function getScanFindings(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/findings`);
  return handleResponse(res);
}

/**
 * Get raw findings list for a scan (flat list).
 * @param {string} scanId
 * @returns {Promise<Array>}
 */
export async function getScanFindingsList(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/findings/list`);
  return handleResponse(res);
}

/**
 * Get assessment plan for a scan (Phase 5).
 * @param {string} scanId
 * @returns {Promise<object>}
 */
export async function getAssessmentPlan(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scans/${scanId}/plan`);
  return handleResponse(res);
}

/**
 * Get assessment tasks for a scan (Phase 5).
 * @param {string} scanId
 * @returns {Promise<object>}
 */
export async function getScanTasks(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scans/${scanId}/tasks`);
  return handleResponse(res);
}

/**
 * Get agent execution results for a scan (Phase 5).
 * @param {string} scanId
 * @returns {Promise<object>}
 */
export async function getAgentResults(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scans/${scanId}/agent-results`);
  return handleResponse(res);
}

/**
 * Get audit trail of Master Agent decisions (Phase 5).
 * @param {string} scanId
 * @returns {Promise<object>}
 */
export async function getScanDecisions(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scans/${scanId}/decisions`);
  return handleResponse(res);
}

/**
 * Get remediation details for a finding.
 * @param {string} scanId
 * @param {number} findingIdx
 * @returns {Promise<object>}
 */
export async function getRemediationDetails(scanId, findingIdx) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/findings/${findingIdx}/remediation`);
  return handleResponse(res);
}

/**
 * Get scan trends (compare with previous scans).
 * @param {string} scanId
 */
export async function getScanTrends(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/trends`);
  return handleResponse(res);
}

// ── Scan Control ────────────────────────────────────────────────────────────────

export async function pauseScan(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/pause`, {
    method: 'POST',
  });
  return handleResponse(res);
}

export async function resumeScan(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/resume`, {
    method: 'POST',
  });
  return handleResponse(res);
}

export async function cancelScan(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/cancel`, {
    method: 'POST',
  });
  return handleResponse(res);
}

// ── AI Analysis ─────────────────────────────────────────────────────────────────

/**
 * Get AI status.
 * @returns {Promise<object>}
 */
export async function getAiStatus() {
  const res = await apiFetch(`${getBaseUrl()}/ai/status`);
  return handleResponse(res);
}

/**
 * Analyze a single finding via AI.
 * @param {number} findingId
 * @param {boolean} simulate
 * @returns {Promise<object>}
 */
export async function analyzeFinding(findingId, simulate = false) {
  const res = await apiFetch(`${getBaseUrl()}/findings/${findingId}/analyze`, {
    method: 'POST',
    body: JSON.stringify({ simulate }),
  });
  return handleResponse(res);
}

/**
 * Analyze all findings in a scan via AI.
 * @param {string} scanId
 * @param {boolean} simulate
 * @returns {Promise<object>}
 */
export async function analyzeScan(scanId, simulate = false) {
  const res = await apiFetch(`${getBaseUrl()}/scans/${scanId}/analyze`, {
    method: 'POST',
    body: JSON.stringify({ simulate }),
  });
  return handleResponse(res);
}

/**
 * Get AI analysis for a finding.
 * @param {number} findingId
 * @returns {Promise<object>}
 */
export async function getFindingAnalysis(findingId) {
  const res = await apiFetch(`${getBaseUrl()}/findings/${findingId}/analysis`);
  return handleResponse(res);
}

// ── Triage ─────────────────────────────────────────────────────────────────────

export async function setFindingTriage(findingId, status, note = '') {
  const res = await apiFetch(`${getBaseUrl()}/findings/${findingId}/triage`, {
    method: 'POST',
    body: JSON.stringify({ status, note }),
  });
  return handleResponse(res);
}

export async function getScanTriage(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/triage`);
  return handleResponse(res);
}

// ── Dashboard & History ───────────────────────────────────────────────────────

export async function getDashboardStats() {
  const res = await apiFetch(`${getBaseUrl()}/dashboard/stats`);
  return handleResponse(res);
}

export async function listAllScans() {
  const res = await apiFetch(`${getBaseUrl()}/scans`);
  return handleResponse(res);
}

// ── Tools ──────────────────────────────────────────────────────────────────────

export async function getToolsStatus() {
  const res = await apiFetch(`${getBaseUrl()}/tools/status`);
  return handleResponse(res);
}

// ── Reports ────────────────────────────────────────────────────────────────────

export async function downloadExecutiveSummary(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/report/executive-summary`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to download' }));
    throw new Error(err.detail || 'Failed to download executive summary');
  }
  return res.blob();
}

export async function downloadTechnicalReport(scanId) {
  const res = await apiFetch(`${getBaseUrl()}/scan/${scanId}/report/technical`);
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to download' }));
    throw new Error(err.detail || 'Failed to download technical report');
  }
  return res.blob();
}

// ── API Keys ───────────────────────────────────────────────────────────────────

export async function listApiKeys() {
  const res = await apiFetch(`${getBaseUrl()}/auth/keys`);
  return handleResponse(res);
}

export async function createApiKey(name = 'default') {
  const apiKey = getApiKey();
  if (!apiKey) {
    // No key in localStorage — use /setup directly (no auth required)
    return await createKeyViaSetup(name);
  }
  // Has a key in localStorage — try the authenticated endpoint
  // If it gets a 401, apiFetch auto-recovers (creates new key via /setup,
  // saves to localStorage, and retries). If that also fails, fall back
  // to /setup directly.
  const res = await apiFetch(`${getBaseUrl()}/auth/keys`, {
    method: 'POST',
    body: JSON.stringify({ name }),
  });
  if (res.ok) {
    return await handleResponse(res);
  }
  // If apiFetch's auto-recovery didn't help (e.g. /setup also failed),
  // try /setup one more time
  return await createKeyViaSetup(name);
}

async function createKeyViaSetup(name) {
  const res = await fetch(`${getBackendBaseUrl()}/setup`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ name }),
  });
  if (res.ok) {
    const data = await res.json();
    localStorage.setItem('cyberpilot_api_key', data.key);
    return { id: 0, name: data.name, key: data.key, key_prefix: data.key.slice(0, 8), created_at: new Date().toISOString() };
  }
  throw new Error('Could not create API key. Is the backend running?');
}

export async function revokeApiKey(keyId) {
  const res = await apiFetch(`${getBaseUrl()}/auth/keys/${keyId}`, {
    method: 'DELETE',
  });
  return handleResponse(res);
}

// ── Health ─────────────────────────────────────────────────────────────────────

export async function checkHealth() {
  const res = await fetch(`${getBackendBaseUrl()}/health`);
  return handleResponse(res);
}

// ── Test exports (internal logic, not part of public API) ─────────────────────
export { apiFetch, recoverApiKey };

export function _resetRecoveryState() {
  isRefreshing = false;
  refreshPromise = null;
}
