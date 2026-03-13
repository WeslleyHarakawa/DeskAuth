/**
 * DeskAuth - 2FA Authenticator for your Desktop
 * Developed by Weslley Harakawa
 * https://weslley.harakawa.tech
 *
 * camera.js — Standalone camera QR scanner tab.
 *
 * Runs in a full Chrome tab (not the popup) so that getUserMedia permission
 * prompts are displayed correctly — popup pages interfere with permission dialogs.
 *
 * Flow:
 *  1. getUserMedia → attach stream to <video>
 *  2. requestAnimationFrame loop → scanFrameForQR each frame
 *  3. On QR found → parseOtpAuthURI → saveAccount → show success
 */

import { scanFrameForQR, parseOtpAuthURI, parseMigrationURI } from './qr-import.js';
import { saveAccount } from './storage.js';

// ── i18n ───────────────────────────────────────────────

/**
 * Returns the translated string for `key`, substituting `{0}`, `{1}` … with
 * the provided positional arguments.
 *
 * @param {string}    key
 * @param {...string} subs
 * @returns {string}
 */
function t(key, ...subs) {
  let msg = chrome.i18n.getMessage(key);
  if (!msg) return key;
  subs.forEach((s, i) => { msg = msg.replace(`{${i}}`, s); });
  return msg;
}

/** Applies data-i18n / data-i18n-html attributes throughout the camera page. */
function applyI18n() {
  document.title = t('camera_page_title');
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const msg = t(/** @type {HTMLElement} */ (el).dataset.i18n ?? '');
    if (msg) el.textContent = msg;
  });
  document.querySelectorAll('[data-i18n-html]').forEach((el) => {
    const msg = t(/** @type {HTMLElement} */ (el).dataset.i18nHtml ?? '');
    if (msg) el.innerHTML = msg;
  });
}

// ── DOM refs ───────────────────────────────────────────

const elVideo    = /** @type {HTMLVideoElement} */ (document.getElementById('video'));
const elStatus   = /** @type {HTMLElement}      */ (document.getElementById('status'));
const elBtnGroup = /** @type {HTMLElement}      */ (document.getElementById('btn-group'));
const elBtnRetry = /** @type {HTMLButtonElement}*/ (document.getElementById('btn-retry'));
const elBtnClose = /** @type {HTMLButtonElement}*/ (document.getElementById('btn-close'));

// ── State ──────────────────────────────────────────────

/** Profile/group assigned to all accounts saved in this session (from URL param). */
const importGroup = new URL(location.href).searchParams.get('group') ?? '';

/** @type {MediaStream|null} */
let stream = null;

/** @type {number|null} */
let rafId = null;

// ── Main ───────────────────────────────────────────────

async function start() {
  // Reset UI state for retry
  setStatus('', 'error');
  elBtnGroup.style.display = 'none';
  elVideo.srcObject = null;

  try {
    stream = await navigator.mediaDevices.getUserMedia({
      video: {
        facingMode: { ideal: 'environment' },
        width:  { ideal: 640 },
        height: { ideal: 480 },
      },
    });
  } catch (err) {
    const name = /** @type {DOMException} */ (err).name;
    const msg =
      name === 'NotFoundError'    ? t('cam_err_not_found') :
      name === 'NotReadableError' ? t('cam_err_not_readable') :
      name === 'NotAllowedError'  ? t('cam_err_not_allowed') :
      t('cam_err_unavailable');
    setStatus(msg, 'error');
    showButtons(false);
    return;
  }

  elVideo.srcObject = stream;
  elVideo.addEventListener('loadedmetadata', () => {
    elVideo.play().catch(() => {});
    scan();
  }, { once: true });
}

function scan() {
  const uri = scanFrameForQR(elVideo);
  if (uri) {
    stopCamera();
    handleQR(uri);
    return;
  }
  rafId = requestAnimationFrame(scan);
}

function stopCamera() {
  if (rafId !== null) { cancelAnimationFrame(rafId); rafId = null; }
  if (stream)         { stream.getTracks().forEach((t) => t.stop()); stream = null; }
}

/**
 * Parses the detected URI, saves the account, and shows a success or error message.
 *
 * @param {string} uri
 */
async function handleQR(uri) {
  // Google Authenticator export — one QR contains multiple accounts
  if (uri.toLowerCase().startsWith('otpauth-migration://')) {
    let accounts;
    try {
      accounts = parseMigrationURI(uri);
    } catch (err) {
      setStatus(t('cam_invalid_migration', err instanceof Error ? err.message : String(err)), 'error');
      showButtons(true);
      return;
    }

    if (accounts.length === 0) {
      setStatus(t('cam_no_totp'), 'error');
      showButtons(true);
      return;
    }

    try {
      for (const account of accounts) await saveAccount({ ...account, ...(importGroup && { group: importGroup }) });
    } catch (err) {
      setStatus(t('cam_save_failed', err instanceof Error ? err.message : String(err)), 'error');
      showButtons(true);
      return;
    }

    const n = accounts.length;

    // Read batch metadata from the URL params (batch_size = total QR count in this export)
    const qm        = uri.indexOf('?');
    const rawParams = qm !== -1 ? uri.slice(qm + 1) : '';
    const bsMatch   = rawParams.match(/[?&]?batch_size=(\d+)/i);
    const biMatch   = rawParams.match(/[?&]?batch_index=(\d+)/i);
    const batchSize  = bsMatch ? parseInt(bsMatch[1],  10) : 1;
    const batchIndex = biMatch ? parseInt(biMatch[1], 10) : 0;
    const hasMore    = batchSize > 1 && batchIndex < batchSize - 1;

    const plural = n > 1 ? 's' : '';
    const msg = hasMore
      ? t('cam_import_batch', String(n), plural, String(batchIndex + 1), String(batchSize))
      : t('cam_import_done', String(n), plural);
    setStatus(msg, 'success');
    showButtons(false);
    return;
  }

  // Standard otpauth:// — single account
  let parsed;
  try {
    parsed = parseOtpAuthURI(uri);
  } catch (err) {
    setStatus(t('cam_invalid_qr', err instanceof Error ? err.message : String(err)), 'error');
    showButtons(true);
    return;
  }

  try {
    await saveAccount({
      issuer:    parsed.issuer,
      name:      parsed.name,
      secret:    parsed.secret,
      period:    parsed.period,
      digits:    parsed.digits,
      algorithm: parsed.algorithm,
      ...(importGroup && { group: importGroup }),
    });
  } catch (err) {
    setStatus(t('cam_save_failed', err instanceof Error ? err.message : String(err)), 'error');
    showButtons(true);
    return;
  }

  const label = parsed.issuer ? `${parsed.issuer} (${parsed.name})` : parsed.name;
  setStatus(t('cam_added', label), 'success');
  showButtons(false);
}

/**
 * @param {string}           msg
 * @param {'success'|'error'} type
 */
function setStatus(msg, type) {
  elStatus.textContent = msg;
  elStatus.className   = type;
}

/**
 * Shows the button group. If `withRetry` is true, the "Try again" button is visible.
 *
 * @param {boolean} withRetry
 */
function showButtons(withRetry) {
  elBtnGroup.style.display = 'flex';
  elBtnRetry.style.display = withRetry ? 'inline-block' : 'none';
}

// ── Bootstrap ──────────────────────────────────────────

elBtnRetry.addEventListener('click', () => { stopCamera(); start(); });
elBtnClose.addEventListener('click', () => window.close());

applyI18n();
start();
