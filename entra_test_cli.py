#!/usr/bin/env python3
"""Helper CLI for exercising Microsoft Entra OIDC endpoints.

This tool walks through the OAuth 2.0 Authorization Code flow with PKCE,
automatically loading client credentials from ``.env``.
It enforces PKCE requirements and exposes a ``report`` subcommand that walks
through discovery, authorization, token, refresh, and userinfo calls to confirm
everything works end-to-end. Both public-client (PKCE + no client secret) and
confidential client scenarios are supported. Works with any Microsoft Entra tenant.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import secrets
import json
import sys
import textwrap
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List
from urllib import error as urlerror
from urllib import parse as urlparse
from urllib import request as urlrequest
import webbrowser

from dotenv import dotenv_values
from flask import Flask, jsonify

DEFAULT_TENANT_ID = "14b77578-9773-42d5-8507-251ca2dc2b06"
DEFAULT_SCOPE = "email openid profile offline_access"
DEFAULT_ENV_FILE = ".env"
GUIDE_DOC_PATH = "../docs/entra-guide.docx"
AUTH_ENDPOINT = (
    "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/authorize"
)
TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
WELL_KNOWN_ENDPOINT = (
    "https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration"
)
USERINFO_ENDPOINT = "https://graph.microsoft.com/oidc/userinfo"
BROWSER_HELPER_HTML = textwrap.dedent(
    """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>Microsoft Entra Browser Helper</title>
      <style>
        body { font-family: sans-serif; margin: 0; padding: 1rem; background: #f7f7f7; }
        h1 { margin-top: 0; }
        section { background: white; border-radius: 8px; padding: 1rem; margin-bottom: 1rem; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
        textarea, input { width: 100%; box-sizing: border-box; font-family: monospace; border-radius: 4px; border: 1px solid #ccc; padding: 0.5rem; }
        textarea { min-height: 4rem; }
        button { padding: 0.5rem 1rem; margin-top: 0.5rem; cursor: pointer; }
        pre { background: #1e1e1e; color: #f5f5f5; padding: 0.5rem; border-radius: 4px; overflow-x: auto; }
        .status { font-size: 0.9rem; color: #444; }
        #report-container { display: flex; flex-direction: column; gap: 0.5rem; }
        .report-entry { border: 1px solid #ddd; border-radius: 6px; padding: 0.5rem; background: #fafafa; }
        .report-status { font-weight: bold; margin-bottom: 0.25rem; }
        .report-detail { font-size: 0.85rem; color: #555; white-space: pre-wrap; }
      </style>
    </head>
    <body>
      <h1>Microsoft Entra Browser Helper</h1>
      <section>
        <p>This helper redeems authorization codes directly in the browser so SPA (cross-origin only) app registrations can be validated. Launch the authorization URL, authenticate with your registered credentials, copy the redirect URL (or just the <code>code</code> value), and paste it below.</p>
        <p class="status">Configuration</p>
        <pre id="config-view">Loading configuration…</pre>
      </section>

      <section>
        <h2>Step 1: Authorization</h2>
        <button id="start-auth">Launch authorization URL</button>
        <p class="status">After signing in, copy the entire redirect URL (even if the page fails) and paste it here.</p>
        <label for="code-input">Redirect URL or authorization code</label>
        <textarea id="code-input" placeholder="https://your-app.example.com/callback?code=...&state=..."></textarea>
        <button id="extract-code">Extract code from URL</button>
        <label for="verifier">PKCE code verifier (auto-filled after launching authorization)</label>
        <input id="verifier" placeholder="Generated automatically" />
      </section>

      <section>
        <h2>Step 2: Token exchange</h2>
        <button id="redeem-code">Redeem authorization code</button>
        <p class="status">Token endpoint response</p>
        <pre id="token-output"></pre>
      </section>

      <section>
        <h2>Step 3: Userinfo (optional)</h2>
        <label for="access-token-input">Paste an access token</label>
        <textarea id="access-token-input" placeholder="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9…"></textarea>
        <button id="call-userinfo">Call Microsoft Graph userinfo</button>
        <p class="status">Userinfo response</p>
        <pre id="userinfo-output"></pre>
      </section>

      <section>
        <h2>Report</h2>
        <p>Mirrors the CLI report output (PASS/SKIP/FAIL).</p>
        <div id="report-container"></div>
      </section>

      <script>
        let configData = null;
        const configView = document.getElementById('config-view');
        const verifierInput = document.getElementById('verifier');
        const codeInput = document.getElementById('code-input');
        const tokenOutput = document.getElementById('token-output');
        const userinfoOutput = document.getElementById('userinfo-output');
        const reportContainer = document.getElementById('report-container');
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

        function renderReport() {
          reportContainer.innerHTML = '';
          reportOrder.forEach((step) => {
            const entry = reportData.get(step);
            const status = entry ? entry.status : 'PENDING';
            const detail = entry ? entry.detail : '';
            const div = document.createElement('div');
            div.className = 'report-entry';
            div.innerHTML = `<div class="report-status">${status}</div><div class="report-name">${step}</div><div class="report-detail">${detail || ''}</div>`;
            reportContainer.appendChild(div);
          });
        }

        function updateReport(name, status, detail) {
          reportData.set(name, { status, detail });
          renderReport();
        }

        renderReport();

        function base64UrlEncode(arrayBuffer) {
          const bytes = new Uint8Array(arrayBuffer);
          let binary = '';
          for (let i = 0; i < bytes.byteLength; i += 1) {
            binary += String.fromCharCode(bytes[i]);
          }
          return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+/g, '');
        }

        function generateVerifier(length = 64) {
          const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
          const randomValues = new Uint8Array(length);
          crypto.getRandomValues(randomValues);
          return Array.from(randomValues, (value) => charset[value % charset.length]).join('');
        }

        async function pkceChallenge(verifier) {
          const data = new TextEncoder().encode(verifier);
          const digest = await crypto.subtle.digest('SHA-256', data);
          return base64UrlEncode(digest);
        }

        function logStatus(element, message) {
          element.textContent = message;
        }

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

        document.getElementById('start-auth').addEventListener('click', startAuthorization);
        document.getElementById('redeem-code').addEventListener('click', redeemCode);
        document.getElementById('extract-code').addEventListener('click', () => {
          const value = extractCode(codeInput.value);
          if (value && value !== codeInput.value.trim()) {
            codeInput.value = value;
          }
        });
        document.getElementById('call-userinfo').addEventListener('click', callUserinfo);

        fetch('/config')
          .then((resp) => resp.json())
          .then((data) => {
            configData = data;
            configView.textContent = JSON.stringify(
              { client_id: data.client_id, redirect_uri: data.redirect_uri, scope: data.scope, tenant_id: data.tenant_id, public_client: data.public_client },
              null,
              2
            );
            updateReport(
              'Load configuration from env',
              'PASS',
              `Client ID loaded (${data.client_id.slice(0, 4)}…); redirect URI ${data.redirect_uri}; client secret ${data.public_client ? 'not required' : 'available'}.`
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
            configView.textContent = 'Failed to load config: ' + err;
            updateReport('Load configuration from env', 'FAIL', 'Failed to load config: ' + err);
          });
      </script>
    </body>
    </html>
    """
)

BROWSER_HELPER_HTML_V2 = textwrap.dedent(
    """
    <!doctype html>
    <html lang="en">
    <head>
      <meta charset="utf-8" />
      <title>Microsoft Entra Browser Helper</title>
      <style>
        body {
          font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
          margin: 0;
          padding: 1.5rem;
          background: #f3f4f6;
          color: #111827;
        }

        .app-shell {
          max-width: 1120px;
          margin: 0 auto;
        }

        .page-header {
          margin-bottom: 1rem;
        }

        h1 {
          margin: 0 0 0.25rem 0;
          font-size: 1.6rem;
        }

        .lead {
          margin: 0;
          color: #4b5563;
          font-size: 0.95rem;
        }

        .layout {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }

        @media (min-width: 900px) {
          .layout {
            flex-direction: row;
            align-items: flex-start;
          }
        }

        .main-column,
        .side-column {
          display: flex;
          flex-direction: column;
          gap: 1rem;
        }

        .main-column {
          flex: 2 1 0;
        }

        .side-column {
          flex: 1 1 0;
        }

        section {
          background: #ffffff;
          border-radius: 10px;
          padding: 1rem;
          box-shadow: 0 1px 3px rgba(15, 23, 42, 0.08);
          border: 1px solid #e5e7eb;
        }

        section h2 {
          margin-top: 0;
          font-size: 1rem;
          margin-bottom: 0.5rem;
        }

        textarea,
        input {
          width: 100%;
          box-sizing: border-box;
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
          border-radius: 6px;
          border: 1px solid #d1d5db;
          padding: 0.5rem;
          font-size: 0.9rem;
          background: #f9fafb;
        }

        textarea {
          min-height: 4rem;
          resize: vertical;
        }

        button {
          padding: 0.45rem 0.9rem;
          border-radius: 999px;
          border: 1px solid transparent;
          font-size: 0.9rem;
          cursor: pointer;
          background: #e5e7eb;
          color: #111827;
        }

        button.primary {
          background: #2563eb;
          color: #ffffff;
          border-color: #2563eb;
        }

        button.secondary {
          background: #ffffff;
          color: #374151;
          border-color: #d1d5db;
        }

        button:hover {
          filter: brightness(0.97);
        }

        .status {
          font-size: 0.85rem;
          color: #6b7280;
          margin-top: 0.25rem;
          margin-bottom: 0.5rem;
        }

        #report-container {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .report-entry {
          border-radius: 8px;
          padding: 0.5rem 0.75rem;
          background: #f9fafb;
          border: 1px solid #e5e7eb;
        }

        .report-status {
          font-weight: 600;
          margin-bottom: 0.1rem;
        }

        .report-name {
          font-size: 0.9rem;
          margin-bottom: 0.1rem;
          color: #111827;
        }

        .report-detail {
          font-size: 0.8rem;
          color: #4b5563;
          white-space: pre-wrap;
        }

        .report-pass {
          border-color: #bbf7d0;
          background: #f0fdf4;
        }

        .report-pass .report-status {
          color: #15803d;
        }

        .report-fail {
          border-color: #fecaca;
          background: #fef2f2;
        }

        .report-fail .report-status {
          color: #b91c1c;
        }

        .report-skip {
          border-color: #fed7aa;
          background: #fffbeb;
        }

        .report-skip .report-status {
          color: #92400e;
        }

        .config-grid {
          display: flex;
          flex-direction: column;
          gap: 0.5rem;
        }

        .config-grid label span {
          display: block;
          font-size: 0.8rem;
          color: #6b7280;
          margin-bottom: 0.15rem;
        }

        .config-checkbox {
          display: flex;
          align-items: center;
          gap: 0.5rem;
          margin-top: 0.5rem;
          font-size: 0.85rem;
          color: #374151;
        }

        .config-checkbox input {
          width: auto;
        }

        .config-actions {
          display: flex;
          flex-wrap: wrap;
          gap: 0.5rem;
          margin-top: 0.75rem;
        }

        pre.output {
          background: #111827;
          color: #e5e7eb;
          padding: 0.5rem;
          border-radius: 6px;
          overflow-x: auto;
          font-size: 0.8rem;
        }

        label {
          font-size: 0.9rem;
          color: #111827;
        }

        code {
          font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace;
          font-size: 0.85rem;
          background: #e5e7eb;
          padding: 0.1rem 0.25rem;
          border-radius: 3px;
        }
      </style>
    </head>
    <body>
      <div class="app-shell">
        <header class="page-header">
          <h1>Microsoft Entra Browser Helper</h1>
          <p class="lead">
            Redeem authorization codes directly in the browser so SPA (cross-origin only) registrations can be validated
            without wiring tokens into your app first.
          </p>
        </header>

        <div class="layout">
          <div class="main-column">
            <section id="auth-section">
              <h2>Step 1: Authorization</h2>
              <p class="status">
                Launch the authorization URL, sign in with your registered credentials, then paste the redirect URL (or just the
                <code>code</code> value) below.
              </p>
              <button id="start-auth" class="primary">Launch authorization URL</button>
              <label for="code-input">Redirect URL or authorization code</label>
              <textarea
                id="code-input"
                placeholder="https://your-app.example.com/callback?code=...&state=..."
              ></textarea>
              <p class="status">You can also paste just the <code>code</code> value.</p>
              <button id="extract-code" class="secondary">Extract code from URL</button>
              <label for="verifier">PKCE code verifier (auto-filled after launching authorization)</label>
              <input id="verifier" placeholder="Generated automatically" />
            </section>

            <section id="token-section">
              <h2>Step 2: Token exchange</h2>
              <p class="status">
                Redeem the authorization code for tokens using the configured client. The helper automatically includes
                PKCE parameters when required.
              </p>
              <button id="redeem-code" class="primary">Redeem authorization code</button>
              <p class="status">Token endpoint response</p>
              <pre id="token-output" class="output"></pre>
            </section>

            <section id="userinfo-section">
              <h2>Step 3: Userinfo (optional)</h2>
              <label for="access-token-input">Paste an access token</label>
              <textarea
                id="access-token-input"
                placeholder="eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9…"
              ></textarea>
              <button id="call-userinfo" class="secondary">Call Microsoft Graph userinfo</button>
              <p class="status">Userinfo response</p>
              <pre id="userinfo-output" class="output"></pre>
            </section>
          </div>

          <div class="side-column">
            <section id="config-section">
              <h2>Configuration</h2>
              <p class="status" id="config-status">Loading configuration from .env…</p>
              <form id="config-form">
                <div class="config-grid">
                  <label>
                    <span>Client ID</span>
                    <input id="config-client-id" autocomplete="off" />
                  </label>
                  <label>
                    <span>Redirect URI</span>
                    <input id="config-redirect-uri" type="url" autocomplete="off" />
                  </label>
                  <label>
                    <span>Scope</span>
                    <input id="config-scope" autocomplete="off" />
                  </label>
                  <label>
                    <span>Tenant ID</span>
                    <input id="config-tenant-id" autocomplete="off" />
                  </label>
                  <label>
                    <span>Discovery URL</span>
                    <input id="config-discovery-url" type="url" autocomplete="off" />
                  </label>
                  <label>
                    <span>State</span>
                    <input id="config-state" autocomplete="off" />
                  </label>
                </div>
                <label class="config-checkbox">
                  <input type="checkbox" id="config-public-client" />
                  <span>Public client (PKCE + no client secret)</span>
                </label>
                <div class="config-actions">
                  <button type="button" id="config-apply" class="primary">Apply changes</button>
                  <button type="button" id="config-reset" class="secondary">Reset to .env values</button>
                </div>
              </form>
            </section>

            <section id="report-section">
              <h2>Report</h2>
              <p class="status">Mirrors the CLI report output (PASS/SKIP/FAIL).</p>
              <div id="report-container"></div>
            </section>
          </div>
        </div>
      </div>

      <script>
        let configData = null;
        let originalConfigData = null;

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

        function updateReport(name, status, detail) {
          reportData.set(name, { status, detail });
          renderReport();
        }

        renderReport();

        function base64UrlEncode(arrayBuffer) {
          const bytes = new Uint8Array(arrayBuffer);
          let binary = '';
          for (let i = 0; i < bytes.byteLength; i += 1) {
            binary += String.fromCharCode(bytes[i]);
          }
          return btoa(binary).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+/g, '');
        }

        function generateVerifier(length = 64) {
          const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~';
          const randomValues = new Uint8Array(length);
          crypto.getRandomValues(randomValues);
          return Array.from(randomValues, (value) => charset[value % charset.length]).join('');
        }

        async function pkceChallenge(verifier) {
          const data = new TextEncoder().encode(verifier);
          const digest = await crypto.subtle.digest('SHA-256', data);
          return base64UrlEncode(digest);
        }

        function logStatus(element, message) {
          if (!element) return;
          element.textContent = message;
        }

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
                'Configuration updated for this browser session (env file unchanged).';
            }
            updateReport(
              'Load configuration from env',
              'PASS',
              'Configuration updated in the helper UI; original .env values remain unchanged.'
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
              configStatus.textContent = 'Reset to values loaded from .env.';
            }
            updateReport(
              'Load configuration from env',
              'PASS',
              'Configuration reset to .env defaults.'
            );
            fetchDiscoveryMetadata(configData.discovery_url);
          });
        }

        fetch('/config')
          .then((resp) => resp.json())
          .then((data) => {
            originalConfigData = Object.assign({}, data);
            configData = Object.assign({}, data);
            populateConfigForm(configData);
            if (configStatus) {
              configStatus.textContent =
                'Loaded from .env; adjust values below to experiment with alternate settings.';
            }
            updateReport(
              'Load configuration from env',
              'PASS',
              `Client ID loaded (${data.client_id.slice(0, 4)}…); redirect URI ${data.redirect_uri}; client secret ${
                data.public_client ? 'not required' : 'available'
              }.`
            );
            if (data.public_client) {
              updateReport(
                'Client credentials grant',
                'SKIP',
                'Public client registrations cannot request app-only tokens.'
              );
            } else {
              updateReport(
                'Client credentials grant',
                'SKIP',
                'Define a scope to test client_credentials from the CLI.'
              );
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
            updateReport(
              'Load configuration from env',
              'FAIL',
              'Failed to load config: ' + err
            );
          });
      </script>
    </body>
    </html>
    """
)


@dataclass
class HttpResponse:
    status: int
    content_type: str
    payload: str


@dataclass
class EntraEnvDefaults:
    client_id: str | None = None
    client_secret: str | None = None
    redirect_uri: str | None = None
    discovery_url: str | None = None
    tenant_id: str = DEFAULT_TENANT_ID


@dataclass
class ReportEntry:
    name: str
    status: str
    detail: str


class SkipStep(Exception):
    """Signal that the step was intentionally skipped."""


def _resolve_public_client(flag: bool | None, client_secret: str | None) -> bool:
    if flag is None:
        return not bool(client_secret)
    return flag


def _encode_query(params: Dict[str, Any]) -> str:
    safe_params = {k: v for k, v in params.items() if v is not None}
    return urlparse.urlencode(safe_params, quote_via=urlparse.quote)


def _generate_code_verifier(length: int = 64) -> str:
    # RFC 7636 allows 43-128 characters; 64-char string sourced from secure random bytes.
    verifier = base64.urlsafe_b64encode(secrets.token_bytes(48)).decode("ascii").rstrip("=")
    if len(verifier) < 43:
        verifier += "A" * (43 - len(verifier))
    return verifier[:128]


def _code_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).decode("ascii").rstrip("=")


def _post_form(url: str, data: Dict[str, Any], timeout: int) -> HttpResponse:
    encoded = _encode_query(data).encode("utf-8")
    req = urlrequest.Request(
        url,
        data=encoded,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    return _execute(req, timeout)


def _get(url: str, headers: Dict[str, str] | None, timeout: int) -> HttpResponse:
    req = urlrequest.Request(url, headers=headers or {})
    return _execute(req, timeout)


def _execute(req: urlrequest.Request, timeout: int) -> HttpResponse:
    try:
        with urlrequest.urlopen(req, timeout=timeout) as resp:
            payload = resp.read().decode("utf-8")
            return HttpResponse(
                status=resp.status,
                content_type=resp.headers.get("Content-Type", ""),
                payload=payload,
            )
    except urlerror.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(
            f"HTTP {exc.code} error while calling {req.full_url}: {body}"
        ) from exc


def _dump_response(response: HttpResponse) -> None:
    if "application/json" in response.content_type:
        parsed = json.loads(response.payload)
        json.dump(parsed, sys.stdout, indent=2, sort_keys=True)
        print()
    else:
        print(response.payload)


def _build_authorization_url(
    tenant_id: str,
    client_id: str,
    redirect_uri: str,
    scope: str,
    response_mode: str,
    response_type: str,
    state: str | None,
    code_challenge: str | None = None,
    code_challenge_method: str | None = None,
) -> str:
    params = {
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "response_mode": response_mode,
        "response_type": response_type,
        "scope": scope,
        "state": state or "none",
    }
    if code_challenge:
        params["code_challenge"] = code_challenge
        params["code_challenge_method"] = code_challenge_method or "S256"
    url = AUTH_ENDPOINT.format(tenant=tenant_id)
    return f"{url}?{_encode_query(params)}"


def _extract_code(value: str) -> str:
    trimmed = value.strip()
    if not trimmed:
        raise SkipStep("Authorization code not provided.")
    parsed = urlparse.urlparse(trimmed)
    if parsed.query:
        query = urlparse.parse_qs(parsed.query)
        code_values = query.get("code")
        if not code_values:
            raise RuntimeError(
                "Redirect URL does not contain a `code` parameter. Paste the full redirect URL or just the code."
            )
        return code_values[0]
    return trimmed


def _determine_env_file(argv: list[str]) -> str:
    env_file = DEFAULT_ENV_FILE
    for idx, arg in enumerate(argv):
        if arg in ("--env-file", "-e"):
            if idx + 1 < len(argv):
                env_file = argv[idx + 1]
        elif arg.startswith("--env-file="):
            env_file = arg.split("=", 1)[1]
        elif arg.startswith("-e="):
            env_file = arg.split("=", 1)[1]
    return env_file


def _tenant_from_discovery_url(url: str | None) -> str | None:
    if not url:
        return None
    parsed = urlparse.urlparse(url)
    parts = [part for part in parsed.path.split("/") if part]
    if parts:
        return parts[0]
    return None


def _load_env_defaults(env_file: str) -> EntraEnvDefaults:
    path = Path(env_file)
    if not path.exists():
        return EntraEnvDefaults()
    values = dotenv_values(path)
    defaults = EntraEnvDefaults(
        client_id=values.get("client_id"),
        client_secret=values.get("client_secret"),
        redirect_uri=values.get("redirect_uri"),
        discovery_url=values.get("discovery_url"),
    )
    tenant = values.get("tenant_id") or _tenant_from_discovery_url(defaults.discovery_url)
    if tenant:
        defaults.tenant_id = tenant
    return defaults


def handle_authorize(args: argparse.Namespace) -> None:
    print(
        f"Step 1 (Authorization Request) from {GUIDE_DOC_PATH}. "
        "Send the user to the following URL and complete the login to capture the code."
    )
    code_challenge = None
    code_verifier = None
    if not args.disable_pkce:
        code_verifier = args.code_verifier or _generate_code_verifier()
        code_challenge = _code_challenge(code_verifier)
    else:
        print(
            "\nPKCE is disabled for this request. Only do this if you are certain the "
            "Entra app registration does not enforce PKCE."
        )
    full_url = _build_authorization_url(
        args.tenant_id,
        args.client_id,
        args.redirect_uri,
        args.scope,
        args.response_mode,
        args.response_type,
        args.state,
        code_challenge=code_challenge,
        code_challenge_method="S256" if code_challenge else None,
    )
    print(
        "\nPaste this authorization URL into a browser and complete the login "
        "flow to obtain a code. Once redirected back, copy the `code` parameter."
    )
    print(full_url)
    if code_verifier:
        print(
            "\nPKCE code verifier (required for the token request):\n"
            f"{code_verifier}\n"
            "Run the token command with `--code-verifier` set to this value."
        )
    print(
        "\nNext: run the `token` subcommand with the copied code and "
        "redirect URI to perform Step 2 from the onboarding guide."
    )


def handle_token(args: argparse.Namespace) -> None:
    public_client = _resolve_public_client(args.public_client, args.client_secret)
    if args.grant_type == "authorization_code":
        if not args.code:
            raise SystemExit("--code is required for the authorization_code grant")
        if not args.redirect_uri:
            raise SystemExit(
                "--redirect-uri is required for the authorization_code grant"
            )
    if args.grant_type == "refresh_token" and not args.refresh_token:
        raise SystemExit("--refresh-token is required for the refresh_token grant")

    if args.grant_type == "client_credentials" and public_client:
        raise SystemExit(
            "Client credentials flow is not available for public clients. Remove --public-client."
        )

    data: Dict[str, Any] = {
        "client_id": args.client_id,
        "grant_type": args.grant_type,
    }
    needs_secret = args.grant_type == "client_credentials" or not public_client
    if needs_secret:
        if not args.client_secret:
            raise SystemExit(
                "--client-secret is required unless you set --public-client for the authorization_code/refresh_token grants."
            )
        data["client_secret"] = args.client_secret

    if args.scope:
        data["scope"] = args.scope
    if args.grant_type == "authorization_code":
        data["code"] = args.code
        data["redirect_uri"] = args.redirect_uri
    elif args.grant_type == "refresh_token":
        data["refresh_token"] = args.refresh_token
    elif args.grant_type == "client_credentials":
        if not args.scope:
            raise SystemExit("--scope is required for the client_credentials grant")
    if args.grant_type == "authorization_code" and args.code_verifier:
        data["code_verifier"] = args.code_verifier

    response = _post_form(
        TOKEN_ENDPOINT.format(tenant=args.tenant_id),
        data,
        timeout=args.timeout,
    )
    _dump_response(response)
    if args.grant_type == "authorization_code":
        print(
            "\nTo continue with Step 3 from the onboarding guide, call the "
            "`userinfo` subcommand with the access token that was just returned."
        )


def handle_userinfo(args: argparse.Namespace) -> None:
    headers = {"Authorization": f"Bearer {args.access_token}"}
    response = _get(USERINFO_ENDPOINT, headers, timeout=args.timeout)
    _dump_response(response)
    print(
        "\nIf you need to refresh tokens without another browser login, store the "
        "refresh_token from the previous step and invoke the `token` command with "
        "`--grant-type refresh_token`."
    )


def handle_well_known(args: argparse.Namespace) -> None:
    url = args.discovery_url or WELL_KNOWN_ENDPOINT.format(tenant=args.tenant_id)
    response = _get(url, headers=None, timeout=args.timeout)
    _dump_response(response)
    print(
        "\nThese metadata values can be plugged into Postman or other tooling if you "
        "need to compare your CLI results with external validators."
    )


def handle_guide(args: argparse.Namespace) -> None:
    defaults: EntraEnvDefaults = args.env_defaults
    config_summary = textwrap.indent(
        "\n".join(
            [
                f"• Client ID present: {'yes' if defaults.client_id else 'no'}",
                f"• Client secret present: {'yes' if defaults.client_secret else 'no'}",
                f"• Redirect URI present: {'yes' if defaults.redirect_uri else 'no'}",
                f"• Discovery URL present: {'yes' if defaults.discovery_url else 'no'}",
                f"• Tenant ID default: {defaults.tenant_id}",
                f"• Scope default: {DEFAULT_SCOPE}",
            ]
        ),
        "        ",
    )
    template = textwrap.dedent(
        """
        Microsoft Entra OIDC validation walkthrough
        ============================================
        This CLI mirrors the steps called out in {doc_path}.

        Recommended sequence:
          1. Authorization Request:
             python scripts/entra_test_cli.py authorize --env-file {env_file}

          2. Token Exchange (authorization_code grant):
             python scripts/entra_test_cli.py token --code <value> --redirect-uri "<redirect>"

          3. User Info lookup:
             python scripts/entra_test_cli.py userinfo --access-token <token>

          4. Metadata inspection:
             python scripts/entra_test_cli.py well-known

        Configuration snapshot ({env_file}):
        {config_summary}

        You can override any parameter on the CLI if you want to test alternate
        tenants or app registrations without editing your Flask configuration.
        """
    ).strip()
    print(
        template.format(
            doc_path=GUIDE_DOC_PATH, env_file=args.env_file, config_summary=config_summary
        )
    )


def handle_report(args: argparse.Namespace) -> None:
    entries: List[ReportEntry] = []
    context: Dict[str, Any] = {}
    use_pkce = not args.disable_pkce
    public_client = _resolve_public_client(args.public_client, args.client_secret)
    if args.code_verifier:
        context["code_verifier"] = args.code_verifier

    def run_step(name: str, func: Callable[[], str]) -> None:
        try:
            detail = func()
            entries.append(ReportEntry(name, "PASS", detail))
        except SkipStep as skip_exc:
            entries.append(ReportEntry(name, "SKIP", str(skip_exc)))
        except Exception as exc:  # noqa: BLE001
            entries.append(ReportEntry(name, "FAIL", str(exc)))

    def step_config() -> str:
        required = [
            ("client_id", bool(args.client_id)),
            ("redirect_uri", bool(args.redirect_uri)),
        ]
        if not public_client:
            required.append(("client_secret", bool(args.client_secret)))

        missing = [label for label, present in required if not present]
        if missing:
            raise RuntimeError(
                f"Missing required values in {args.env_file}: {', '.join(missing)}."
            )
        if public_client and args.client_secret:
            secret_detail = "Client secret: loaded (not sent for public-client flow)"
        elif public_client:
            secret_detail = "Client secret: not required for public-client flow"
        else:
            secret_detail = "Client secret: loaded"
        details = textwrap.indent(
            "\n".join(
                [
                    f"Client ID: loaded ({len(args.client_id)} chars)",
                    f"Redirect URI: {args.redirect_uri}",
                    secret_detail,
                ]
            ),
            "  ",
        )
        return details

    def step_discovery() -> str:
        discovery_url = args.discovery_url or WELL_KNOWN_ENDPOINT.format(tenant=args.tenant_id)
        response = _get(discovery_url, headers=None, timeout=args.timeout)
        payload = json.loads(response.payload)
        issuer = payload.get("issuer", "<unknown>")
        token_endpoint = payload.get("token_endpoint", "<unknown>")
        return textwrap.indent(
            f"Issuer: {issuer}\nToken endpoint: {token_endpoint}", "  "
        )

    def step_client_credentials() -> str:
        if public_client:
            raise SkipStep(
                "Client credentials grant skipped because this app is registered as a public client."
            )
        scope = args.client_credentials_scope
        if not scope:
            raise SkipStep(
                "No client-credentials scope supplied. Provide "
                "`--client-credentials-scope` to exercise this step."
            )
        data = {
            "client_id": args.client_id,
            "client_secret": args.client_secret,
            "grant_type": "client_credentials",
            "scope": scope,
        }
        response = _post_form(
            TOKEN_ENDPOINT.format(tenant=args.tenant_id),
            data,
            timeout=args.timeout,
        )
        parsed = json.loads(response.payload)
        context["client_credentials"] = parsed
        expires = parsed.get("expires_in", "unknown")
        token_chars = len(parsed.get("access_token", ""))
        detail = (
            f"Issued client_credentials access token "
            f"(length {token_chars} chars, expires in {expires}s)."
        )
        return textwrap.indent(detail, "  ")

    def step_authorization() -> str:
        if args.authorization_code:
            if use_pkce and "code_verifier" not in context:
                raise RuntimeError(
                    "PKCE is required for this flow. Supply --code-verifier with the value used when obtaining the code."
                )
            extracted = _extract_code(args.authorization_code)
            context["authorization_code"] = extracted
            return textwrap.indent("Authorization code supplied via CLI options.", "  ")

        if args.non_interactive:
            raise SkipStep(
                "Authorization code not provided and prompts are disabled (--non-interactive)."
            )

        if use_pkce and "code_verifier" not in context:
            context["code_verifier"] = _generate_code_verifier()
        code_verifier = context.get("code_verifier")
        code_challenge = (
            _code_challenge(code_verifier) if use_pkce and code_verifier else None
        )
        url = _build_authorization_url(
            args.tenant_id,
            args.client_id,
            args.redirect_uri,
            args.scope,
            args.response_mode,
            args.response_type,
            args.state,
            code_challenge=code_challenge,
            code_challenge_method="S256" if code_challenge else None,
        )
        context["authorization_url"] = url
        message = [
            "Open the authorization URL above in a browser.",
            "Complete the login and paste the resulting redirect URL or code.",
        ]
        print("\n".join(message))
        if args.open_browser:
            webbrowser.open(url)
        if code_verifier:
            print(
                "\nPKCE code verifier for this session "
                "(you only need this if you re-run with --authorization-code):\n"
                f"{code_verifier}\n"
            )
        print("\nAuthorization URL:\n", url, "\n", sep="")
        raw_input = input(
            "Paste the redirect URL or authorization code (leave blank to skip): "
        ).strip()
        code = raw_input or None
        if not code:
            raise SkipStep(
                "Authorization code not provided. "
                "Re-run with --authorization-code or allow interactive prompts."
            )
        extracted = _extract_code(code)
        context["authorization_code"] = extracted
        return textwrap.indent("Authorization code captured via interactive login.", "  ")

    def step_token() -> str:
        code = context.get("authorization_code")
        if not code:
            raise SkipStep(
                "No authorization code captured; token exchange skipped."
            )
        code_verifier = context.get("code_verifier")
        if use_pkce and not code_verifier:
            raise RuntimeError(
                "PKCE code verifier missing. Capture the code and verifier in the same run or provide --code-verifier."
            )
        data = {
            "client_id": args.client_id,
            "client_secret": args.client_secret,
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": args.redirect_uri,
            "scope": args.scope,
        }
        if public_client:
            data.pop("client_secret", None)
        if code_verifier:
            data["code_verifier"] = code_verifier
        response = _post_form(
            TOKEN_ENDPOINT.format(tenant=args.tenant_id),
            data,
            timeout=args.timeout,
        )
        parsed = json.loads(response.payload)
        context["auth_tokens"] = parsed
        expires = parsed.get("expires_in", "unknown")
        has_refresh = "refresh_token" in parsed
        detail_lines = [
            f"Received access token (length {len(parsed.get('access_token', ''))} chars).",
            f"Expires in: {expires} seconds.",
            f"Refresh token issued: {'yes' if has_refresh else 'no'}.",
        ]
        return textwrap.indent("\n".join(detail_lines), "  ")

    def step_refresh() -> str:
        refresh_token = (
            args.refresh_token
            or (context.get("auth_tokens") or {}).get("refresh_token")
        )
        if not refresh_token:
            raise SkipStep(
                "No refresh token available. Ensure offline_access scope is granted."
            )
        data = {
            "client_id": args.client_id,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": args.scope,
        }
        if not public_client:
            data["client_secret"] = args.client_secret
        response = _post_form(
            TOKEN_ENDPOINT.format(tenant=args.tenant_id),
            data,
            timeout=args.timeout,
        )
        parsed = json.loads(response.payload)
        context["refresh_tokens"] = parsed
        expires = parsed.get("expires_in", "unknown")
        return textwrap.indent(
            f"Refresh token exchanged successfully (new access token expires in {expires}s).",
            "  ",
        )

    def step_userinfo() -> str:
        token_source = context.get("auth_tokens") or {}
        access_token = args.access_token or token_source.get("access_token")
        if not access_token:
            raise SkipStep("No access token available for userinfo call.")
        response = _get(
            USERINFO_ENDPOINT,
            headers={"Authorization": f"Bearer {access_token}"},
            timeout=args.timeout,
        )
        claims = json.loads(response.payload)
        important = {
            key: claims.get(key)
            for key in ("sub", "email", "name", "preferred_username")
            if claims.get(key) is not None
        }
        summary = "\n".join(f"{k}: {v}" for k, v in important.items()) or "No standard claims returned."
        return textwrap.indent(summary, "  ")

    run_step(f"Load configuration from {args.env_file}", step_config)
    run_step("Fetch OIDC discovery metadata", step_discovery)
    run_step("Client credentials grant", step_client_credentials)
    run_step("Authorization code capture", step_authorization)
    run_step("Exchange authorization code for tokens", step_token)
    run_step("Refresh token exchange", step_refresh)
    run_step("Userinfo endpoint call", step_userinfo)

    print("\nMicrosoft Entra validation report\n=================================")
    for entry in entries:
        header = f"[{entry.status}] {entry.name}"
        print(header)
        print(textwrap.indent(entry.detail, "    "))
        print()
    failures = [e for e in entries if e.status == "FAIL"]
    if failures:
        if any("AADSTS9002327" in entry.detail for entry in failures):
            print(
                "Hint: Microsoft Entra treated this app as a SPA. Use the `browser-helper` "
                "subcommand to redeem the authorization code directly in the browser."
            )
        raise SystemExit("One or more steps failed. See report above for details.")


def handle_browser_helper(args: argparse.Namespace) -> None:
    public_client = _resolve_public_client(args.public_client, args.client_secret)
    if not args.client_id or not args.redirect_uri:
        raise SystemExit("Both --client-id and --redirect-uri are required to launch the browser helper.")
    app = Flask(__name__)
    token_endpoint = TOKEN_ENDPOINT.format(tenant=args.tenant_id)
    auth_endpoint = AUTH_ENDPOINT.format(tenant=args.tenant_id)
    config_payload: Dict[str, Any] = {
        "client_id": args.client_id,
        "redirect_uri": args.redirect_uri,
        "scope": args.scope,
        "tenant_id": args.tenant_id,
        "token_endpoint": token_endpoint,
        "authorization_endpoint": auth_endpoint,
        "userinfo_endpoint": USERINFO_ENDPOINT,
        "discovery_url": args.discovery_url or WELL_KNOWN_ENDPOINT.format(tenant=args.tenant_id),
        "state": args.state,
        "public_client": public_client,
    }
    if not public_client and args.client_secret:
        config_payload["client_secret"] = args.client_secret

    @app.get("/")
    def index() -> str:
        return BROWSER_HELPER_HTML_V2

    @app.get("/config")
    def config() -> Any:
        return jsonify(config_payload)

    helper_url = f"http://{args.host}:{args.port}"
    print(
        textwrap.dedent(
            f"""
            Browser helper running at {helper_url}

            1. Open the URL above in a browser.
            2. Click "Launch authorization URL" and complete the login with your credentials.
            3. Paste the redirect URL (or just the code) back into the helper page and use it to
               redeem tokens via the browser, which satisfies Microsoft Entra's SPA restrictions.
            """
        ).strip()
    )
    if getattr(args, "open_browser", False):
        browser_choice = getattr(args, "browser", "default")
        try:
            if browser_choice == "firefox":
                webbrowser.get("firefox").open(helper_url)
            elif browser_choice == "chromium":
                try:
                    from playwright.sync_api import sync_playwright  # type: ignore[import]
                except Exception as exc:  # pragma: no cover - environment specific
                    print(
                        "Warning: failed to import Playwright for Chromium launch. "
                        "Install it in this environment and run "
                        "`python -m playwright install`.\n"
                        f"Details: {exc}",
                        file=sys.stderr,
                    )
                else:
                    def _open_with_playwright() -> None:
                        with sync_playwright() as p:
                            browser = p.chromium.launch(headless=False)
                            page = browser.new_page()
                            page.goto(helper_url)
                            # Keep the window open for interactive use.
                            page.wait_for_timeout(24 * 60 * 60 * 1000)

                    threading.Thread(target=_open_with_playwright, daemon=True).start()
            else:
                webbrowser.open(helper_url)
        except webbrowser.Error as exc:  # pragma: no cover - best-effort helper
            print(f"Warning: failed to launch browser ({browser_choice}): {exc}", file=sys.stderr)
    app.run(host=args.host, port=args.port, use_reloader=False)


def build_parser(defaults: EntraEnvDefaults, env_file: str) -> argparse.ArgumentParser:
    description = textwrap.dedent(
        f"""
        Validate Microsoft Entra OIDC credentials before wiring them into the Flask app.

        Typical flow from {GUIDE_DOC_PATH}:
          1. Run `authorize` to build the login URL and sign in.
          2. Execute `token --code ... --redirect-uri ...` to obtain tokens.
          3. Call `userinfo` with the access token to confirm claims.
          4. Inspect tenant metadata via `well-known`.
        """
    ).strip()
    parser = argparse.ArgumentParser(
        description=description,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.set_defaults(env_defaults=defaults)
    parser.add_argument(
        "--env-file",
        default=env_file,
        help="Path to the .env file containing Entra settings (default: %(default)s).",
    )
    parser.add_argument(
        "--tenant-id",
        default=defaults.tenant_id,
        help=(
            "Entra tenant ID. Defaults to the tenant extracted from the discovery URL in "
            "your env file or a default tenant ID when unavailable."
        ),
    )
    parser.add_argument(
        "--scope",
        default=DEFAULT_SCOPE,
        help=(
            "Requested scopes when contacting Entra "
            "(default: %(default)s)."
        ),
    )
    parser.add_argument(
        "--discovery-url",
        default=defaults.discovery_url,
        help=(
            "Full OIDC discovery URL. Defaults to the value in your env file; "
            "if omitted, the CLI derives it from the tenant ID."
        ),
    )
    parser.add_argument(
        "--timeout",
        default=30,
        type=int,
        help="HTTP timeout in seconds (default: %(default)s).",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    authorize = subparsers.add_parser(
        "authorize", help="Generate an authorization URL."
    )
    authorize.add_argument(
        "--client-id",
        default=defaults.client_id,
        required=defaults.client_id is None,
        help="Application client ID (default: read from the env file).",
    )
    authorize.add_argument(
        "--redirect-uri",
        default=defaults.redirect_uri,
        required=defaults.redirect_uri is None,
        help="Registered redirect URL that Entra should send the code to.",
    )
    authorize.add_argument(
        "--response-mode",
        default="query",
        help="Response mode to request from Entra (default: %(default)s).",
    )
    authorize.add_argument(
        "--response-type",
        default="code",
        help="OIDC response_type (default: %(default)s).",
    )
    authorize.add_argument("--state", default="none", help="Opaque state value.")
    authorize.add_argument(
        "--code-verifier",
        help="PKCE code verifier to use. If omitted, a secure random value is generated.",
    )
    authorize.add_argument(
        "--disable-pkce",
        action="store_true",
        help="Do not attach PKCE parameters. Only use if the app registration does not require PKCE.",
    )
    authorize.set_defaults(func=handle_authorize)

    token = subparsers.add_parser(
        "token", help="Call the Entra token endpoint."
    )
    token.add_argument(
        "--client-id",
        default=defaults.client_id,
        required=defaults.client_id is None,
        help="Application client ID (default: read from the env file).",
    )
    token.add_argument(
        "--client-secret",
        default=defaults.client_secret,
        help=(
            "Application client secret (default: read from the env file). "
            "Optional when --public-client is supplied."
        ),
    )
    token.add_argument(
        "--grant-type",
        default="authorization_code",
        choices=("authorization_code", "refresh_token", "client_credentials"),
        help="Token grant type to execute (default: %(default)s).",
    )
    token.add_argument("--code", help="Authorization code returned from Entra.")
    token.add_argument("--refresh-token", help="Refresh token to exchange.")
    token.add_argument(
        "--redirect-uri",
        default=defaults.redirect_uri,
        help="Redirect URI used during the authorization request.",
    )
    token.add_argument(
        "--code-verifier",
        help="PKCE code verifier used when initiating the authorization request.",
    )
    token.add_argument(
        "--public-client",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Indicate whether this registration is a public client (PKCE + no client secret). "
            "Defaults to true when no client secret is configured."
        ),
    )
    token.set_defaults(func=handle_token)

    userinfo = subparsers.add_parser(
        "userinfo", help="Call the Microsoft Graph OIDC userinfo endpoint."
    )
    userinfo.add_argument(
        "--access-token",
        required=True,
        help="Bearer token returned from the token endpoint.",
    )
    userinfo.set_defaults(func=handle_userinfo)

    well_known = subparsers.add_parser(
        "well-known", help="Inspect the tenant's OIDC discovery document."
    )
    well_known.set_defaults(func=handle_well_known)

    guide = subparsers.add_parser(
        "guide",
        help="Summarize the onboarding steps and show which values were loaded from the env file.",
    )
    guide.set_defaults(func=handle_guide)

    report = subparsers.add_parser(
        "report",
        help="Run the full Entra validation workflow and emit a pass/fail report.",
    )
    report.add_argument(
        "--client-id",
        default=defaults.client_id,
        required=defaults.client_id is None,
        help="Application client ID (default: read from the env file).",
    )
    report.add_argument(
        "--client-secret",
        default=defaults.client_secret,
        help="Application client secret (default: read from the env file).",
    )
    report.add_argument(
        "--redirect-uri",
        default=defaults.redirect_uri,
        required=defaults.redirect_uri is None,
        help="Registered redirect URL used in the authorization request.",
    )
    report.add_argument(
        "--response-mode",
        default="query",
        help="Response mode to request from Entra (default: %(default)s).",
    )
    report.add_argument(
        "--response-type",
        default="code",
        help="OIDC response_type (default: %(default)s).",
    )
    report.add_argument("--state", default="none", help="Opaque state value.")
    report.add_argument(
        "--authorization-code",
        help="Authorization code or redirect URL to use instead of prompting.",
    )
    report.add_argument(
        "--code-verifier",
        help="PKCE code verifier that matches the provided authorization code.",
    )
    report.add_argument(
        "--refresh-token",
        help="Refresh token to test. Defaults to the value returned during report execution.",
    )
    report.add_argument(
        "--access-token",
        help="Access token to pass to the userinfo step. Defaults to the token retrieved earlier.",
    )
    report.add_argument(
        "--client-credentials-scope",
        help="Scope to use for the client_credentials test (example: api://<app-id>/.default).",
    )
    report.add_argument(
        "--disable-pkce",
        action="store_true",
        help="Do not include PKCE parameters when generating the authorization URL (not recommended).",
    )
    report.add_argument(
        "--public-client",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Treat this registration as a public client (no client secret required for delegated grants). "
            "Defaults to true if no client secret is configured."
        ),
    )
    report.add_argument(
        "--non-interactive",
        action="store_true",
        help="Do not prompt for missing inputs during the report run.",
    )
    report.add_argument(
        "--open-browser",
        action="store_true",
        help="Attempt to open the authorization URL in the default browser when prompting for the code.",
    )
    report.set_defaults(func=handle_report)

    browser = subparsers.add_parser(
        "browser-helper",
        help="Launch a local browser UI to perform SPA-style token exchanges.",
    )
    browser.add_argument(
        "--client-id",
        default=defaults.client_id,
        required=defaults.client_id is None,
        help="Application client ID (default: read from the env file).",
    )
    browser.add_argument(
        "--client-secret",
        default=defaults.client_secret,
        help="Client secret to expose to the browser helper (only when --no-public-client is supplied).",
    )
    browser.add_argument(
        "--redirect-uri",
        default=defaults.redirect_uri,
        required=defaults.redirect_uri is None,
        help="Registered redirect URL that receives the authorization code.",
    )
    browser.add_argument(
        "--scope",
        default=DEFAULT_SCOPE,
        help="Requested scopes when contacting Entra (default: %(default)s).",
    )
    browser.add_argument(
        "--state",
        default="none",
        help="Opaque state value included in the authorization URL.",
    )
    browser.add_argument(
        "--tenant-id",
        default=defaults.tenant_id,
        help="Tenant that hosts the Entra app (default: %(default)s).",
    )
    browser.add_argument(
        "--host",
        default="127.0.0.1",
        help="Host/IP to bind the helper web server to (default: %(default)s).",
    )
    browser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="Port to bind the helper web server to (default: %(default)s).",
    )
    browser.add_argument(
        "--discovery-url",
        default=defaults.discovery_url,
        help="OIDC discovery URL (default: derived from the tenant).",
    )
    browser.add_argument(
        "--open-browser",
        action="store_true",
        help="Open the helper URL in a browser after starting the server.",
    )
    browser.add_argument(
        "--browser",
        choices=("default", "firefox", "chromium"),
        default="default",
        help=(
            "When used with --open-browser, choose which browser to launch. "
            "Use 'firefox' to target a Firefox installation, or 'chromium' "
            "to launch a Playwright-managed Chromium window from this environment."
        ),
    )
    browser.add_argument(
        "--public-client",
        action=argparse.BooleanOptionalAction,
        default=None,
        help=(
            "Treat the registration as a public client (PKCE only, no client secret). "
            "Defaults to true if no client secret is configured."
        ),
    )
    browser.set_defaults(func=handle_browser_helper)

    return parser


def main(argv: list[str] | None = None) -> None:
    if argv is None:
        argv = sys.argv[1:]
    env_file = _determine_env_file(argv)
    defaults = _load_env_defaults(env_file)
    parser = build_parser(defaults, env_file)
    args = parser.parse_args(argv)
    try:
        args.func(args)
    except RuntimeError as exc:
        parser.exit(status=1, message=f"{exc}\n")


if __name__ == "__main__":
    main()
