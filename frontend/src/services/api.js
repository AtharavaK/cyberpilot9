const DEFAULT_BASE_URL = 'http://localhost:8000/api/v1';

function getBaseUrl() {
  return localStorage.getItem('cyberpilot_api_url') || import.meta.env.VITE_API_URL || DEFAULT_BASE_URL;
}

function getApiKey() {
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

/**
 * Start a new security scan.
 * @param {string} targetUrl
 * @returns {Promise<{scan_id: string, status: string, message: string}>}
 */
export async function startScan(targetUrl, simulate = true) {
  const res = await fetch(`${getBaseUrl()}/scan/start`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ target_url: targetUrl, simulate }),
  });
  return handleResponse(res);
}

/**
 * Poll the status/result of a scan by its ID.
 * @param {string} scanId
 * @returns {Promise<object>}
 */
export async function getScanStatus(scanId) {
  const res = await fetch(`${getBaseUrl()}/scan/${scanId}/status`, {
    headers: getHeaders(),
  });
  return handleResponse(res);
}

/**
 * Download executive summary PDF.
 * @param {string} scanId
 * @returns {Promise<Blob>}
 */
export async function downloadExecutiveSummary(scanId) {
  const res = await fetch(`${getBaseUrl()}/scan/${scanId}/report/executive-summary`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to download' }));
    throw new Error(err.detail || 'Failed to download executive summary');
  }
  return res.blob();
}

/**
 * Download technical report PDF.
 * @param {string} scanId
 * @returns {Promise<Blob>}
 */
export async function downloadTechnicalReport(scanId) {
  const res = await fetch(`${getBaseUrl()}/scan/${scanId}/report/technical`, {
    headers: getHeaders(),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: 'Failed to download' }));
    throw new Error(err.detail || 'Failed to download technical report');
  }
  return res.blob();
}

/**
 * List all API keys (requires auth).
 * @returns {Promise<Array>}
 */
export async function listApiKeys() {
  const res = await fetch(`${getBaseUrl()}/auth/keys`, {
    headers: getHeaders(),
  });
  return handleResponse(res);
}

/**
 * Create a new API key (requires auth, or bootstrap if no keys exist).
 * @param {string} name
 * @returns {Promise<{id: number, name: string, key: string, key_prefix: string, created_at: string}>}
 */
export async function createApiKey(name = 'default') {
  const res = await fetch(`${getBaseUrl()}/auth/keys`, {
    method: 'POST',
    headers: getHeaders(),
    body: JSON.stringify({ name }),
  });
  return handleResponse(res);
}

/**
 * Revoke an API key.
 * @param {number} keyId
 * @returns {Promise<{message: string}>}
 */
export async function revokeApiKey(keyId) {
  const res = await fetch(`${getBaseUrl()}/auth/keys/${keyId}`, {
    method: 'DELETE',
    headers: getHeaders(),
  });
  return handleResponse(res);
}

/**
 * List all scans (requires auth).
 * @returns {Promise<Array>}
 */
export async function listAllScans() {
  const res = await fetch(`${getBaseUrl()}/scans`, {
    headers: getHeaders(),
  });
  return handleResponse(res);
}
