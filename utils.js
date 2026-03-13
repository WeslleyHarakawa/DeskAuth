/**
 * DeskAuth - 2FA Authenticator for your Desktop
 * Developed by Weslley Harakawa
 * https://weslley.harakawa.tech
 *
 * utils.js — Common helper utilities shared across the extension.
 */

// ── ID generation ──────────────────────────────────────

/**
 * Generates a cryptographically random UUID v4.
 *
 * Uses the native crypto.randomUUID() when available (Chrome 92+),
 * falling back to manual construction via crypto.getRandomValues().
 *
 * @returns {string} A UUID v4 string (e.g. "550e8400-e29b-41d4-a716-446655440000").
 */
export function generateId() {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID();
  }

  // Fallback: construct UUID v4 manually.
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);

  // Set version bits (v4)
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  // Set variant bits (RFC 4122)
  bytes[8] = (bytes[8] & 0x3f) | 0x80;

  const hex = [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');

  return [
    hex.slice(0, 8),
    hex.slice(8, 12),
    hex.slice(12, 16),
    hex.slice(16, 20),
    hex.slice(20),
  ].join('-');
}

// ── Clipboard ──────────────────────────────────────────

/**
 * Copies a string to the system clipboard.
 *
 * Uses the modern Clipboard API with a fallback for restricted environments.
 *
 * @param {string} text - The text to copy.
 * @returns {Promise<boolean>} - Resolves to true on success, false on failure.
 */
export async function copyToClipboard(text) {
  try {
    if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
      await navigator.clipboard.writeText(text);
      return true;
    }

    // Fallback: execCommand (deprecated but may work in some extension contexts).
    const el = document.createElement('textarea');
    el.value = text;
    el.style.cssText = 'position:fixed;opacity:0;pointer-events:none;';
    document.body.appendChild(el);
    el.select();
    const ok = document.execCommand('copy');
    document.body.removeChild(el);
    return ok;
  } catch (err) {
    console.error('[DeskAuth] copyToClipboard failed:', err);
    return false;
  }
}

// ── Toast notifications ────────────────────────────────

/** @type {HTMLElement | null} Singleton toast element. */
let toastEl = null;

/** @type {ReturnType<typeof setTimeout> | null} */
let toastTimer = null;

/**
 * Displays a brief toast notification at the bottom of the popup.
 *
 * @param {string}                        message  - Text to display.
 * @param {'success' | 'error' | 'info'}  [type]   - Visual style (default: 'info').
 * @param {number}                        [duration] - Display time in ms (default: 2000).
 */
export function showToast(message, type = 'info', duration = 2000) {
  if (!toastEl) {
    toastEl = document.createElement('div');
    toastEl.className = 'toast';
    document.body.appendChild(toastEl);
  }

  // Clear any pending hide timer.
  if (toastTimer) {
    clearTimeout(toastTimer);
    toastTimer = null;
  }

  toastEl.textContent = message;
  toastEl.className   = `toast toast--${type} toast--visible`;

  toastTimer = setTimeout(() => {
    if (toastEl) toastEl.classList.remove('toast--visible');
    toastTimer = null;
  }, duration);
}

// ── String utilities ───────────────────────────────────

/**
 * Validates that a string is a legal base32-encoded secret.
 *
 * Accepts the RFC 4648 alphabet (A–Z, 2–7) plus optional '=' padding.
 *
 * @param {string} value
 * @returns {boolean}
 */
export function isValidBase32(value) {
  return /^[A-Z2-7]+=*$/i.test(value.trim());
}

/**
 * Normalises a base32 secret: strips whitespace, converts to uppercase,
 * and removes '=' padding characters.
 *
 * @param {string} value
 * @returns {string}
 */
export function normaliseBase32(value) {
  return value.trim().toUpperCase().replace(/\s+/g, '').replace(/=/g, '');
}

// ── Time utilities ─────────────────────────────────────

/**
 * Returns the current Unix timestamp in whole seconds.
 *
 * @returns {number}
 */
export function unixNow() {
  return Math.floor(Date.now() / 1000);
}

// ── Encoding ───────────────────────────────────────────

/**
 * Encodes a Uint8Array to a URL-safe base64 string (no padding).
 *
 * TODO: Used by crypto.js — move there if only needed internally.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function uint8ToBase64(bytes) {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decodes a URL-safe base64 string to a Uint8Array.
 *
 * @param {string} b64
 * @returns {Uint8Array}
 */
export function base64ToUint8(b64) {
  const std = b64.replace(/-/g, '+').replace(/_/g, '/');
  const raw = atob(std);
  return Uint8Array.from(raw, (c) => c.charCodeAt(0));
}
