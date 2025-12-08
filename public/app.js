/**
 * Microsoft Entra Browser Helper
 * OAuth 2.0 / OIDC validation tool for testing SPA registrations
 * All logic runs in the browser; no backend required.
 */

let configData = null;
let originalConfigData = null;

// DOM elements
const verifierInput = document.getElementById('verifier');
const codeInput = document.getElementById('code-input');
const tokenOutput = document.getElementById('token-output');
const userinfoOutput = document.getElementById('userinfo-output');
const reportContainer = document.getElementById('report-container');
const configStatus = document.getElementById('config-status');

const clientIdInput = document.getElementById('config-client-id');
const redirectUriInput = document.getElementById('config-redirect-uri');
const scopeInput = document.getElementById('config-scope');
const tenantIdInput = document.getElementById('config-tenant-id');
const discoveryInput = document.getElementById('config-discovery-url');
const stateInput = document.getElementById('config-state');
const publicClientCheckbox = document.getElementById('config-public-client');
const applyButton = document.getElementById('config-apply');
const resetButton = document.getElementById('config-reset');

// Report management
const reportOrder = [
  'Load configuration from env',
  'Fetch OIDC discovery metadata',
  'Client credentials grant',
  'Authorization code capture',
  'Exchange authorization code for tokens',
  'Refresh token exchange',
  'Userinfo endpoint call'
];
const reportData = new Map();

/**
 * Render the report display from stored data
 */
function renderReport() {
  reportContainer.innerHTML = '';
  reportOrder.forEach((step) => {
    const entry = reportData.get(step);
    const status = entry ? entry.status : 'PENDING';
    const detail = entry ? entry.detail : '';
    const normalized = status.toLowerCase();
    const div = document.createElement('div');
    div.className = 'report-entry report-' + normalized;
    div.innerHTML = `<div class="report-status">${status}</div><div class="report-name">${step}</div><div class="report-detail">${detail || ''}</div>`;
    reportContainer.appendChild(div);
  });
}

/**
 * Update a single report entry
 */
function updateReport(name, status, detail) {
  reportData.set(name, { status, detail });
  renderReport();
}

renderReport();

/**
 * Base64URL encode (for PKCE)
 */
function base64UrlEncode(arrayBuffer) {
  const bytes = new Uint8Array(arrayBuffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i += 1) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+/g, '');
}

/**
 * Generate PKCE verifier (64 random characters)
 */
function generateVerifier(length = 64) {
  const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
  const randomValues = new Uint8Array(length);
  crypto.getRandomValues(randomValues);
  return Array.from(randomValues, (value) => charset[value % charset.length]).join('');
}

/**
 * Generate PKCE code challenge (SHA-256 hash of verifier)
 */
async function pkceChallenge(verifier) {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest('SHA-256', data);
  return base64UrlEncode(digest);
}

/**
 * Log status to an element
 */
function logStatus(element, message) {
  if (!element) return;
  element.textContent = message;
}

/**
 * Extract authorization code from redirect URL
 */
function extractCode(value) {
  if (!value) return '';
  const trimmed = value.trim();
  if (trimmed.startsWith('http')) {
    try {
      const url = new URL(trimmed);
      const code = url.searchParams.get('code');
      if (code) {
        return code;
      }
    } catch (err) {
      console.warn('Unable to parse URL', err);
    }
  }
  return trimmed;
}

/**
 * Populate form fields from config data
 */
function populateConfigForm(data) {
  if (!data) return;
  clientIdInput.value = data.client_id || '';
  redirectUriInput.value = data.redirect_uri || '';
  scopeInput.value = data.scope || '';
  tenantIdInput.value = data.tenant_id || '';
  discoveryInput.value = data.discovery_url || '';
  stateInput.value = data.state || 'none';
  publicClientCheckbox.checked = !!data.public_client;
}

/**
 * Read config data from form fields
 */
function readConfigFromForm(current) {
  const base = Object.assign({}, current || {});
  base.client_id = clientIdInput.value.trim();
  base.redirect_uri = redirectUriInput.value.trim();
  base.scope = scopeInput.value.trim();
  base.tenant_id = tenantIdInput.value.trim();
  base.discovery_url = discoveryInput.value.trim();
  base.state = stateInput.value.trim() || 'none';
  base.public_client = publicClientCheckbox.checked;
  return base;
}

/**
 * Fetch and parse OIDC discovery metadata
 */
async function fetchDiscoveryMetadata(url) {
  if (!url) {
    updateReport('Fetch OIDC discovery metadata', 'SKIP', 'Discovery URL not provided.');
    return;
  }
  try {
    const resp = await fetch(url);
    const meta = await resp.json();
    updateReport('Fetch OIDC discovery metadata', 'PASS', `Issuer: ${meta.issuer}`);
  } catch (err) {
    updateReport('Fetch OIDC discovery metadata', 'FAIL', 'Failed to load discovery metadata: ' + err);
  }
}

/**
 * Launch authorization flow in a new window
 */
async function startAuthorization() {
  if (!configData) return;
  const verifier = generateVerifier();
  sessionStorage.setItem('pkce_verifier', verifier);
  verifierInput.value = verifier;
  const challenge = await pkceChallenge(verifier);
  const params = new URLSearchParams({
    client_id: configData.client_id,
    response_type: 'code',
    response_mode: 'query',
    redirect_uri: configData.redirect_uri,
    scope: configData.scope,
    state: configData.state,
    code_challenge: challenge,
    code_challenge_method: 'S256',
  });
  const authUrl = configData.authorization_endpoint + '?' + params.toString();
  window.open(authUrl, '_blank');
  logStatus(tokenOutput, 'Authorization launched. Paste the redirect URL after login.');
}

/**
 * Redeem authorization code for tokens
 */
async function redeemCode() {
  if (!configData) return;
  const codeValue = extractCode(codeInput.value);
  if (!codeValue) {
    alert('Please provide a redirect URL or authorization code.');
    updateReport('Authorization code capture', 'FAIL', 'No redirect URL or code provided.');
    return;
  }
  updateReport('Authorization code capture', 'PASS', 'Authorization code captured from input.');
  const verifier = verifierInput.value.trim() || sessionStorage.getItem('pkce_verifier');
  if (!verifier) {
    alert('Missing PKCE code verifier. Launch the authorization URL again.');
    return;
  }
  const params = new URLSearchParams({
    client_id: configData.client_id,
    grant_type: 'authorization_code',
    code: codeValue,
    redirect_uri: configData.redirect_uri,
    scope: configData.scope,
    code_verifier: verifier,
  });
  if (!configData.public_client && configData.client_secret) {
    params.append('client_secret', configData.client_secret);
  }
  logStatus(tokenOutput, 'Submitting authorization code to the token endpoint…');
  const response = await fetch(configData.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  const text = await response.text();
  tokenOutput.textContent = text;
  if (response.ok) {
    updateReport('Exchange authorization code for tokens', 'PASS', 'Token endpoint returned an access token.');
    try {
      const parsed = JSON.parse(text);
      if (parsed.access_token) {
        document.getElementById('access-token-input').value = parsed.access_token;
      }
      await refreshStep(parsed);
    } catch (err) {
      updateReport('Refresh token exchange', 'SKIP', 'Token response was not JSON; refresh skipped.');
    }
  } else {
    updateReport('Exchange authorization code for tokens', 'FAIL', text);
    updateReport('Refresh token exchange', 'SKIP', 'Token exchange failed; refresh not attempted.');
  }
}

/**
 * Refresh access token using refresh token
 */
async function refreshStep(parsed) {
  const refreshToken = parsed.refresh_token;
  if (!refreshToken) {
    updateReport('Refresh token exchange', 'SKIP', 'No refresh token issued (missing offline_access scope?).');
    return;
  }
  const params = new URLSearchParams({
    client_id: configData.client_id,
    grant_type: 'refresh_token',
    refresh_token: refreshToken,
    scope: configData.scope,
  });
  if (!configData.public_client && configData.client_secret) {
    params.append('client_secret', configData.client_secret);
  }
  const response = await fetch(configData.token_endpoint, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: params.toString(),
  });
  const text = await response.text();
  if (response.ok) {
    updateReport('Refresh token exchange', 'PASS', 'Refresh token successfully exchanged.');
  } else {
    updateReport('Refresh token exchange', 'FAIL', text);
  }
}

/**
 * Call Microsoft Graph userinfo endpoint with access token
 */
async function callUserinfo() {
  const token = document.getElementById('access-token-input').value.trim();
  if (!token) {
    alert('Provide an access token first.');
    return;
  }
  logStatus(userinfoOutput, 'Calling userinfo…');
  const response = await fetch(configData.userinfo_endpoint, {
    headers: { Authorization: 'Bearer ' + token },
  });
  const text = await response.text();
  userinfoOutput.textContent = text;
  if (response.ok) {
    updateReport('Userinfo endpoint call', 'PASS', 'Graph userinfo returned claims.');
  } else {
    updateReport('Userinfo endpoint call', 'FAIL', text);
  }
}

/**
 * Initialize event listeners
 */
document.getElementById('start-auth').addEventListener('click', startAuthorization);
document.getElementById('redeem-code').addEventListener('click', redeemCode);
document.getElementById('extract-code').addEventListener('click', () => {
  const value = extractCode(codeInput.value);
  if (value && value !== codeInput.value.trim()) {
    codeInput.value = value;
  }
});
document.getElementById('call-userinfo').addEventListener('click', callUserinfo);

if (applyButton) {
  applyButton.addEventListener('click', () => {
    if (!configData) return;
    configData = readConfigFromForm(configData);
    if (configStatus) {
      configStatus.textContent =
        'Configuration updated for this browser session (config.json unchanged).';
    }
    updateReport(
      'Load configuration from env',
      'PASS',
      'Configuration updated in the helper UI; original config.json values remain unchanged.'
    );
    fetchDiscoveryMetadata(configData.discovery_url);
  });
}

if (resetButton) {
  resetButton.addEventListener('click', () => {
    if (!originalConfigData) return;
    configData = Object.assign({}, originalConfigData);
    populateConfigForm(configData);
    if (configStatus) {
      configStatus.textContent = 'Reset to config.json values.';
    }
    updateReport(
      'Load configuration from env',
      'PASS',
      'Configuration reset to config.json defaults.'
    );
    fetchDiscoveryMetadata(configData.discovery_url);
  });
}

/**
 * Load configuration from config.json
 */
fetch('config.json')
  .then((resp) => {
    if (!resp.ok) {
      throw new Error(`Failed to load config.json: ${resp.status}`);
    }
    return resp.json();
  })
  .then((data) => {
    originalConfigData = Object.assign({}, data);
    configData = Object.assign({}, data);
    populateConfigForm(configData);
    if (configStatus) {
      configStatus.textContent =
        'Loaded from config.json; adjust values below to experiment with alternate settings.';
    }
    updateReport(
      'Load configuration from env',
      'PASS',
      `Client ID loaded (${data.client_id.slice(0, 4)}…); redirect URI ${data.redirect_uri}; client secret ${
        data.public_client ? 'not required' : 'available'
      }.`
    );
    if (data.public_client) {
      updateReport('Client credentials grant', 'SKIP', 'Public client registrations cannot request app-only tokens.');
    } else {
      updateReport('Client credentials grant', 'SKIP', 'Define a scope to test client_credentials from the CLI.');
    }
    if (sessionStorage.getItem('pkce_verifier')) {
      verifierInput.value = sessionStorage.getItem('pkce_verifier');
    }
    fetchDiscoveryMetadata(data.discovery_url);
  })
  .catch((err) => {
    if (configStatus) {
      configStatus.textContent = 'Failed to load config: ' + err;
    }
    updateReport('Load configuration from env', 'FAIL', 'Failed to load config.json: ' + err);
  });
