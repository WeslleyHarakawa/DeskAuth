/**
 * DeskAuth - 2FA Authenticator for your Desktop
 * Developed by Weslley Harakawa
 * https://weslley.harakawa.tech
 *
 * popup.js — Controls popup UI logic.
 *
 * Responsibilities:
 *  - Render account cards with live TOTP codes and per-account countdown timers
 *  - Efficiently refresh codes only when the time window changes (not every tick)
 *  - Open / close the "Add Account" modal with Base32 validation
 *  - Delegate persistence to storage.js
 *  - Delegate code generation to totp.js
 *  - Delegate QR parsing to qr-import.js
 *
 * Tick architecture:
 *  - setInterval(1s) → tickCards() updates countdown/progress bars (always, sync)
 *  - refreshCode(account) fires async only when timeStep changes for that account
 *  - codeCache prevents duplicate HMAC calls within the same time window
 */

import { getAccounts, saveAccount, deleteAccount, updateAccount } from './storage.js';
import {
  generateTOTP,
  timeStep,
  secondsRemaining,
  DEFAULT_PERIOD,
  DEFAULT_DIGITS,
  DEFAULT_ALGORITHM,
} from './totp.js';
import { copyToClipboard, showToast, isValidBase32, normaliseBase32 } from './utils.js';

// ── i18n helpers ───────────────────────────────────────

/**
 * Returns the translated string for `key`, substituting `{0}`, `{1}` … with
 * the provided positional arguments.
 *
 * Falls back to the key itself when the message is missing (dev safety net).
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

/**
 * Applies Chrome i18n translations to every element that carries a
 * `data-i18n*` attribute.  Call once after the DOM is ready.
 */
function applyI18n() {
  document.querySelectorAll('[data-i18n]').forEach((el) => {
    const msg = t(/** @type {HTMLElement} */ (el).dataset.i18n ?? '');
    if (msg) el.textContent = msg;
  });
  document.querySelectorAll('[data-i18n-html]').forEach((el) => {
    const msg = t(/** @type {HTMLElement} */ (el).dataset.i18nHtml ?? '');
    if (msg) el.innerHTML = msg;
  });
  document.querySelectorAll('[data-i18n-placeholder]').forEach((el) => {
    const msg = t(/** @type {HTMLElement} */ (el).dataset.i18nPlaceholder ?? '');
    if (msg) /** @type {HTMLInputElement} */ (el).placeholder = msg;
  });
  document.querySelectorAll('[data-i18n-aria-label]').forEach((el) => {
    const msg = t(/** @type {HTMLElement} */ (el).dataset.i18nAriaLabel ?? '');
    if (msg) el.setAttribute('aria-label', msg);
  });
  document.querySelectorAll('[data-i18n-title]').forEach((el) => {
    const msg = t(/** @type {HTMLElement} */ (el).dataset.i18nTitle ?? '');
    if (msg) /** @type {HTMLElement} */ (el).title = msg;
  });
}

// ── Lazy QR import (loads jsQR only when user triggers Scan/Import) ──────────

/** @type {Promise<typeof import('./qr-import.js')>|null} */
let _qrImportPromise = null;

/** Returns the qr-import module, loading jsQR on first call only. */
function getQrImport() {
  if (!_qrImportPromise) _qrImportPromise = import('./qr-import.js');
  return _qrImportPromise;
}

// ── DOM references ─────────────────────────────────────

const elAccountList = /** @type {HTMLElement} */ (document.getElementById('account-list'));
const elEmptyState  = /** @type {HTMLElement} */ (document.getElementById('empty-state'));

const elBtnAddAccount = /** @type {HTMLButtonElement} */ (document.getElementById('btn-add-account'));
const elBtnImportQR   = /** @type {HTMLButtonElement} */ (document.getElementById('btn-import-qr'));

const elModal        = /** @type {HTMLElement}       */ (document.getElementById('modal-add'));
const elBtnCancel    = /** @type {HTMLButtonElement} */ (document.getElementById('btn-modal-cancel'));
const elBtnSave      = /** @type {HTMLButtonElement} */ (document.getElementById('btn-modal-save'));
const elInputIssuer  = /** @type {HTMLInputElement}  */ (document.getElementById('input-issuer'));
const elInputAccount = /** @type {HTMLInputElement}  */ (document.getElementById('input-account'));
const elInputSecret  = /** @type {HTMLInputElement}  */ (document.getElementById('input-secret'));

const elModalImportSource     = /** @type {HTMLElement}       */ (document.getElementById('modal-import-source'));
const elBtnImportFromFile     = /** @type {HTMLButtonElement} */ (document.getElementById('btn-import-from-file'));
const elBtnImportFromCamera   = /** @type {HTMLButtonElement} */ (document.getElementById('btn-import-from-camera'));
const elBtnImportSourceCancel = /** @type {HTMLButtonElement} */ (document.getElementById('btn-import-source-cancel'));
const elInputImportGroup      = /** @type {HTMLInputElement}  */ (document.getElementById('input-import-group'));
const elImportGroupError      = /** @type {HTMLElement}       */ (document.getElementById('import-group-error'));

const elProfileSelect  = /** @type {HTMLSelectElement} */ (document.getElementById('profile-select'));
const elInputGroup     = /** @type {HTMLInputElement}  */ (document.getElementById('input-group'));
const elGroupDatalist  = /** @type {HTMLElement}       */ (document.getElementById('group-datalist'));

const elModalCamera     = /** @type {HTMLElement}       */ (document.getElementById('modal-camera'));
const elCameraVideo     = /** @type {HTMLVideoElement}  */ (document.getElementById('camera-video'));
const elBtnCameraCancel = /** @type {HTMLButtonElement} */ (document.getElementById('btn-camera-cancel'));
const elCameraDeniedHint  = /** @type {HTMLElement}      */ (document.getElementById('camera-denied-hint'));
const elCameraDeniedSteps = /** @type {HTMLOListElement} */ (document.getElementById('camera-denied-steps'));

const elModalOrganize     = /** @type {HTMLElement}       */ (document.getElementById('modal-organize'));
const elOrganizeList      = /** @type {HTMLElement}       */ (document.getElementById('organize-list'));
const elBtnOrganizeCancel = /** @type {HTMLButtonElement} */ (document.getElementById('btn-organize-cancel'));
const elBtnOrganizeSave   = /** @type {HTMLButtonElement} */ (document.getElementById('btn-organize-save'));

const elModalHelp    = /** @type {HTMLElement}       */ (document.getElementById('modal-help'));
const elBtnHelp      = /** @type {HTMLButtonElement} */ (document.getElementById('btn-help'));
const elBtnHelpClose = /** @type {HTMLButtonElement} */ (document.getElementById('btn-help-close'));

const elModalEdit        = /** @type {HTMLElement}       */ (document.getElementById('modal-edit'));
const elEditInputIssuer  = /** @type {HTMLInputElement}  */ (document.getElementById('edit-input-issuer'));
const elEditInputName    = /** @type {HTMLInputElement}  */ (document.getElementById('edit-input-name'));
const elEditInputGroup   = /** @type {HTMLInputElement}  */ (document.getElementById('edit-input-group'));
const elBtnEditCancel    = /** @type {HTMLButtonElement} */ (document.getElementById('btn-edit-cancel'));
const elBtnEditSave      = /** @type {HTMLButtonElement} */ (document.getElementById('btn-edit-save'));

const elModalConfirmDelete     = /** @type {HTMLElement}       */ (document.getElementById('modal-confirm-delete'));
const elConfirmDeleteName      = /** @type {HTMLElement}       */ (document.getElementById('confirm-delete-name'));
const elBtnConfirmDeleteCancel = /** @type {HTMLButtonElement} */ (document.getElementById('btn-confirm-delete-cancel'));
const elBtnConfirmDeleteOk     = /** @type {HTMLButtonElement} */ (document.getElementById('btn-confirm-delete-ok'));

const elSearchBar       = /** @type {HTMLElement}      */ (document.getElementById('search-bar'));
const elSearchInput     = /** @type {HTMLInputElement} */ (document.getElementById('search-input'));
const elSearchNoResults = /** @type {HTMLElement}      */ (document.getElementById('search-no-results'));

// ── State ──────────────────────────────────────────────

/** @type {import('./storage.js').Account[]} */
let accounts = [];

/** @type {number|null} setInterval handle */
let tickIntervalId = null;

/**
 * Per-account code cache.
 * Maps accountId → { code: string, step: number }
 * `step` is the timeStep() value when the code was generated,
 * so we skip re-generation when the same window is still active.
 *
 * @type {Map<string, { code: string, step: number }>}
 */
const codeCache = new Map();

/**
 * Guard set: accounts whose async refreshCode() is currently in-flight.
 * Prevents duplicate concurrent HMAC calls for the same account.
 *
 * @type {Set<string>}
 */
const refreshInFlight = new Set();

/** Currently selected profile filter. Empty string = show all. */
let activeGroup = '';

/** Current search query — filters visible cards in real-time. */
let searchQuery = '';

// ── Profile selector ───────────────────────────────────

/** Returns a sorted list of unique non-empty group values across all accounts. */
function getUniqueGroups() {
  return [...new Set(accounts.map((a) => a.group).filter(Boolean))].sort();
}

/**
 * Rebuilds the profile <select> options and the group <datalist>
 * to reflect the current accounts list.
 */
function updateProfileSelector() {
  const groups = getUniqueGroups();

  elProfileSelect.innerHTML = '';

  if (groups.length === 0) {
    // No profiles yet — show placeholder
    const placeholder = document.createElement('option');
    placeholder.value    = '';
    placeholder.disabled = true;
    placeholder.selected = true;
    placeholder.textContent = t('no_profiles');
    elProfileSelect.appendChild(placeholder);
  } else {
    // Show only profile names
    for (const g of groups) {
      const opt = document.createElement('option');
      opt.value       = g;
      opt.textContent = g;
      if (g === activeGroup) opt.selected = true;
      elProfileSelect.appendChild(opt);
    }

    // Auto-select first profile if activeGroup was deleted or never set
    if (!activeGroup || !groups.includes(activeGroup)) {
      activeGroup = groups[0];
      elProfileSelect.value = activeGroup;
    }
  }

  // Rebuild <datalist> for group inputs
  elGroupDatalist.innerHTML = groups.map((g) => `<option value="${escHtml(g)}"></option>`).join('');
}

// ── TOTP helpers ───────────────────────────────────────

/**
 * Resolves TOTP parameters for an account, applying defaults where missing.
 *
 * @param {import('./storage.js').Account} account
 * @returns {{ period: number, digits: number, algorithm: string }}
 */
function totpParams(account) {
  return {
    period:    account.period    ?? DEFAULT_PERIOD,
    digits:    account.digits    ?? DEFAULT_DIGITS,
    algorithm: account.algorithm ?? DEFAULT_ALGORITHM,
  };
}

/**
 * Asynchronously generates a fresh TOTP code for one account and updates
 * the cache and the corresponding DOM card.
 *
 * The `refreshInFlight` guard ensures that only one in-flight request
 * exists per account at any time, even if tickCards fires before the
 * previous async call resolved.
 *
 * @param {import('./storage.js').Account} account
 */
async function refreshCode(account) {
  if (refreshInFlight.has(account.id)) return;

  const { period, digits, algorithm } = totpParams(account);
  const step = timeStep(period);

  // Check cache — another concurrent call may have already populated this step
  const cached = codeCache.get(account.id);
  if (cached?.step === step) return;

  refreshInFlight.add(account.id);

  try {
    const code = await generateTOTP(account.secret, { period, digits, algorithm });

    codeCache.set(account.id, { code, step });
    applyCodeToCard(account.id, code);
  } finally {
    refreshInFlight.delete(account.id);
  }
}

/**
 * Fires refreshCode for every account concurrently.
 * Used on initial render and after account list changes.
 */
function refreshAllCodes() {
  for (const account of accounts) {
    refreshCode(account); // intentionally not awaited — fire-and-forget
  }
}

// ── DOM update helpers ─────────────────────────────────

/**
 * Updates just the code element of a card (called from refreshCode).
 *
 * @param {string} accountId
 * @param {string} code
 */
function applyCodeToCard(accountId, code) {
  const card = elAccountList.querySelector(`[data-id="${accountId}"]`);
  if (!card) return;

  const elCode = card.querySelector('.account-card__code');
  if (elCode) elCode.textContent = formatCode(code, code === 'INVALID' ? 0 : code.length);

  // Keep dataset in sync for click-to-copy
  /** @type {HTMLElement} */ (card).dataset.code = code;
}

/**
 * Updates the countdown badge, progress bar, and urgency classes for one card.
 *
 * @param {HTMLElement} card
 * @param {number}      secsLeft - Seconds remaining in the current period.
 * @param {number}      period   - Period length in seconds (for progress calc).
 */
function applyTickToCard(card, secsLeft, period) {
  const progress = Math.max(0, (secsLeft / period) * 100);
  const urgency  = secsLeft <= 5  ? 'crit'
                 : secsLeft <= 10 ? 'warn'
                 : '';

  const elCountdown = card.querySelector('.account-card__countdown');
  const elProgress  = /** @type {HTMLElement|null} */ (card.querySelector('.account-card__progress'));
  const elCode      = card.querySelector('.account-card__code');

  if (elCountdown) elCountdown.textContent = String(secsLeft);
  if (elProgress)  elProgress.style.width  = `${progress}%`;

  // Apply urgency modifier classes to countdown, progress, and code
  const targets = [
    { el: elCountdown, base: 'account-card__countdown' },
    { el: elProgress,  base: 'account-card__progress'  },
    { el: elCode,      base: 'account-card__code'       },
  ];

  for (const { el, base } of targets) {
    if (!el) continue;
    el.classList.remove(`${base}--warn`, `${base}--crit`);
    if (urgency) el.classList.add(`${base}--${urgency}`);
  }
}

// ── Init ───────────────────────────────────────────────

async function init() {
  applyI18n();
  accounts = await getAccounts();
  renderAccounts();
  refreshAllCodes();
  startTickLoop();
}

// ── Render ─────────────────────────────────────────────

/**
 * Fully rebuilds the account list DOM.
 * Called on init and after any account mutation (add / delete).
 */
function renderAccounts() {
  elAccountList.innerHTML = '';
  codeCache.clear();
  refreshInFlight.clear();

  updateProfileSelector();

  const visible = activeGroup
    ? accounts.filter((a) => a.group === activeGroup)
    : accounts;

  if (visible.length === 0) {
    elEmptyState.hidden = false;
    elSearchBar.hidden  = true;
    return;
  }

  elEmptyState.hidden = true;
  elSearchBar.hidden  = false;

  for (const account of visible) {
    elAccountList.appendChild(buildAccountCard(account));
  }

  filterCards();
}

/**
 * Shows/hides cards based on `searchQuery` without rebuilding the DOM.
 * Runs in O(n) on existing card nodes — no TOTP timers are disrupted.
 */
function filterCards() {
  const q = searchQuery.trim().toLowerCase();
  const cards = /** @type {NodeListOf<HTMLElement>} */ (
    elAccountList.querySelectorAll('.account-card')
  );
  let visibleCount = 0;
  for (const card of cards) {
    const issuer = (card.querySelector('.account-card__issuer')?.textContent ?? '').toLowerCase();
    const name   = (card.querySelector('.account-card__name')?.textContent   ?? '').toLowerCase();
    const match  = !q || issuer.includes(q) || name.includes(q);
    card.hidden  = !match;
    if (match) visibleCount++;
  }
  elSearchNoResults.hidden = visibleCount > 0 || !q;
}

/**
 * Builds a single account card DOM node.
 *
 * Codes start as '······' placeholder; refreshCode() fills them in
 * asynchronously within milliseconds of the card being appended.
 *
 * @param {import('./storage.js').Account} account
 * @returns {HTMLElement}
 */
function buildAccountCard(account) {
  const { period } = totpParams(account);
  const secsLeft   = secondsRemaining(period);
  const progress   = Math.max(0, (secsLeft / period) * 100);
  const urgency    = secsLeft <= 5  ? 'crit'
                   : secsLeft <= 10 ? 'warn'
                   : '';

  const card = document.createElement('div');
  card.className   = 'account-card';
  card.dataset.id  = account.id;
  card.dataset.code = ''; // will be filled by refreshCode

  card.innerHTML = `
    <div class="account-card__meta">
      ${account.issuer
        ? `<span class="account-card__issuer">${escHtml(account.issuer)}</span>`
        : ''}
      <span class="account-card__name">${escHtml(account.name)}</span>
      ${account.group && !activeGroup
        ? `<span class="account-card__group">${escHtml(account.group)}</span>`
        : ''}
    </div>

    <div class="account-card__countdown${urgency ? ` account-card__countdown--${urgency}` : ''}">
      ${secsLeft}
    </div>

    <div class="account-card__code-row">
      <div class="account-card__code${urgency ? ` account-card__code--${urgency}` : ''}">
        ······
      </div>
      <button
        class="account-card__copy"
        title="${escHtml(t('card_copy_title'))}"
        aria-label="${escHtml(t('card_copy_aria', account.name))}"
      ><svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg></button>
    </div>

    <div class="account-card__progress${urgency ? ` account-card__progress--${urgency}` : ''}"
         style="width:${progress}%"></div>

    <button
      class="account-card__edit"
      title="${escHtml(t('card_edit_title'))}"
      aria-label="${escHtml(t('card_edit_aria', account.name))}"
    >✎</button>

    <button
      class="account-card__delete"
      title="${escHtml(t('card_remove_title'))}"
      aria-label="${escHtml(t('card_remove_aria', account.name))}"
    >✕</button>
  `;

  // Click card body → copy current code
  card.addEventListener('click', (e) => {
    if (/** @type {HTMLElement} */ (e.target).closest('.account-card__delete')) return;
    if (/** @type {HTMLElement} */ (e.target).closest('.account-card__edit'))   return;
    if (/** @type {HTMLElement} */ (e.target).closest('.account-card__copy'))   return;
    const currentCode = card.dataset.code ?? '';
    if (currentCode && currentCode !== 'INVALID') {
      handleCopyCode(card, currentCode, account.name);
    }
  });

  // Copy button
  card.querySelector('.account-card__copy')
    ?.addEventListener('click', () => {
      const currentCode = card.dataset.code ?? '';
      if (currentCode && currentCode !== 'INVALID') {
        handleCopyCode(card, currentCode, account.name);
      }
    });

  // Edit button
  card.querySelector('.account-card__edit')
    ?.addEventListener('click', () => openEditModal(account.id));

  // Delete button
  card.querySelector('.account-card__delete')
    ?.addEventListener('click', () => handleDeleteAccount(account.id));

  return card;
}

// ── Tick loop ──────────────────────────────────────────

/**
 * Called every second.
 *
 * - Updates countdown badges and progress bars (synchronous, cheap).
 * - Triggers an async code refresh only when the time-step has advanced
 *   for a given account — this typically fires once per 30 seconds, not
 *   once per second.
 */
function tickCards() {
  for (const account of accounts) {
    const { period } = totpParams(account);
    const secsLeft   = secondsRemaining(period);
    const step       = timeStep(period);

    const card = /** @type {HTMLElement|null} */ (
      elAccountList.querySelector(`[data-id="${account.id}"]`)
    );
    if (!card) continue;

    // Always update the visual tick (countdown + progress bar)
    applyTickToCard(card, secsLeft, period);

    // Only regenerate the HMAC code when we've entered a new time window
    const cached = codeCache.get(account.id);
    if (!cached || cached.step !== step) {
      refreshCode(account); // async, fire-and-forget
    }
  }
}

function startTickLoop() {
  if (tickIntervalId !== null) clearInterval(tickIntervalId);
  tickIntervalId = setInterval(tickCards, 1000);
}

// ── Actions ────────────────────────────────────────────

/**
 * Copies a TOTP code to the clipboard and shows transient visual feedback.
 *
 * @param {HTMLElement} card
 * @param {string}      code  - The numeric code string (no spaces).
 * @param {string}      label - Account name for the toast message.
 */
async function handleCopyCode(card, code, label) {
  // Strip any display formatting before copying
  const raw = code.replace(/\s/g, '');
  const ok  = await copyToClipboard(raw);

  if (ok) {
    card.classList.add('account-card--copied');
    showToast(t('toast_copied', label), 'success');
    setTimeout(() => card.classList.remove('account-card--copied'), 1500);
  } else {
    showToast(t('toast_copy_failed'), 'error');
  }
}

/**
 * Opens the confirm-delete modal for the given account ID.
 *
 * @param {string} id
 */
function handleDeleteAccount(id) {
  const account = accounts.find((a) => a.id === id);
  const label = account
    ? (account.issuer ? `${account.issuer} — ${account.name}` : account.name)
    : t('card_this_account');
  elConfirmDeleteName.textContent = label;
  elBtnConfirmDeleteOk.dataset.deleteId = id;
  elModalConfirmDelete.hidden = false;
}

async function confirmDeleteAccount() {
  const id = elBtnConfirmDeleteOk.dataset.deleteId;
  elModalConfirmDelete.hidden = true;
  if (!id) return;
  await deleteAccount(id);
  accounts = await getAccounts();
  renderAccounts();
  refreshAllCodes();
}

// ── Organize Profiles modal ────────────────────────────

function openOrganizeModal() {
  elOrganizeList.innerHTML = '';
  for (const account of accounts) {
    const row = document.createElement('div');
    row.className  = 'organize-row';
    row.dataset.id = account.id;
    row.innerHTML  = `
      <div class="organize-row__label">
        ${account.issuer ? `<span class="organize-row__issuer">${escHtml(account.issuer)}</span>` : ''}
        <span class="organize-row__name">${escHtml(account.name)}</span>
      </div>
      <input class="organize-row__input" type="text"
             placeholder="${escHtml(t('organize_no_profile'))}"
             value="${escHtml(account.group ?? '')}"
             list="group-datalist"
             aria-label="${escHtml(t('organize_profile_for', account.name))}" />
    `;
    elOrganizeList.appendChild(row);
  }
  elModalOrganize.hidden = false;
}

async function handleOrganizeSave() {
  elBtnOrganizeSave.disabled = true;
  try {
    const rows = /** @type {NodeListOf<HTMLElement>} */ (elOrganizeList.querySelectorAll('.organize-row'));
    for (const row of rows) {
      const id      = row.dataset.id ?? '';
      const input   = /** @type {HTMLInputElement} */ (row.querySelector('.organize-row__input'));
      const group   = input?.value.trim() ?? '';
      const account = accounts.find((a) => a.id === id);
      if (!account) continue;
      if ((account.group ?? '') !== group) await updateAccount(id, { group });
    }
    accounts = await getAccounts();
    elModalOrganize.hidden = true;
    renderAccounts();
    refreshAllCodes();
  } catch (err) {
    console.error('[DeskAuth] handleOrganizeSave:', err);
    showToast(t('toast_organize_failed'), 'error');
  } finally {
    elBtnOrganizeSave.disabled = false;
  }
}

// ── Help ────────────────────────────────────────────────

function openHelp() {
  elModalHelp.hidden = false;
}

// ── Edit Account modal ─────────────────────────────────

/**
 * Opens the edit modal pre-filled with the given account's current values.
 * @param {string} id
 */
function openEditModal(id) {
  const account = accounts.find((a) => a.id === id);
  if (!account) return;
  elEditInputIssuer.value = account.issuer ?? '';
  elEditInputName.value   = account.name;
  elEditInputGroup.value  = account.group ?? '';
  elBtnEditSave.dataset.editId = id;
  elModalEdit.hidden = false;
  elEditInputName.focus();
}

async function handleEditSave() {
  const id = elBtnEditSave.dataset.editId;
  if (!id) return;

  const name = elEditInputName.value.trim();
  if (!name) {
    showToast(t('toast_name_required'), 'error');
    elEditInputName.focus();
    return;
  }

  elBtnEditSave.disabled = true;
  try {
    await updateAccount(id, {
      issuer: elEditInputIssuer.value.trim(),
      name,
      group:  elEditInputGroup.value.trim(),
    });
    accounts = await getAccounts();
    elModalEdit.hidden = true;
    renderAccounts();
    refreshAllCodes();
  } catch (err) {
    console.error('[DeskAuth] handleEditSave:', err);
    showToast(t('toast_edit_failed'), 'error');
  } finally {
    elBtnEditSave.disabled = false;
  }
}

// ── Add Account modal ──────────────────────────────────

function openAddModal() {
  elInputIssuer.value  = '';
  elInputAccount.value = '';
  elInputSecret.value  = '';
  elInputGroup.value   = activeGroup;
  elModal.hidden = false;
  elInputAccount.focus();
}

function closeAddModal() {
  elModal.hidden = true;
}

async function handleSaveAccount() {
  const issuer = elInputIssuer.value.trim();
  const name   = elInputAccount.value.trim();
  const secret = normaliseBase32(elInputSecret.value);

  if (!name) {
    showToast(t('toast_name_required'), 'error');
    elInputAccount.focus();
    return;
  }

  if (!secret) {
    showToast(t('toast_secret_required'), 'error');
    elInputSecret.focus();
    return;
  }

  // Validate Base32 format before saving
  if (!isValidBase32(secret)) {
    showToast(t('toast_secret_invalid'), 'error');
    elInputSecret.focus();
    return;
  }

  elBtnSave.disabled = true;

  try {
    const group = elInputGroup.value.trim();
    await saveAccount({ issuer, name, secret, ...(group && { group }) });
    accounts = await getAccounts();
    closeAddModal();
    renderAccounts();
    refreshAllCodes();
    showToast(t('toast_added', name), 'success');
  } catch (err) {
    console.error('[DeskAuth] handleSaveAccount:', err);
    showToast(t('toast_save_failed'), 'error');
  } finally {
    elBtnSave.disabled = false;
  }
}

// ── QR Import ──────────────────────────────────────────

// ── Source picker modal ────────────────────────────────

function openImportSourceModal() {
  elInputImportGroup.value   = '';   // always start blank — user must type the profile name
  elInputImportGroup.classList.remove('form-input--error');
  elImportGroupError.hidden  = true;
  elModalImportSource.hidden = false;
}

/**
 * Validates that a profile name was entered before importing.
 * Returns the trimmed group string, or null if validation fails.
 * @returns {string|null}
 */
function validateImportGroup() {
  const group = elInputImportGroup.value.trim();
  if (!group) {
    elInputImportGroup.classList.add('form-input--error');
    elImportGroupError.hidden = false;
    elInputImportGroup.focus();
    return null;
  }
  elInputImportGroup.classList.remove('form-input--error');
  elImportGroupError.hidden = true;
  return group;
}

function closeImportSourceModal() {
  elModalImportSource.hidden = true;
  elCameraDeniedHint.hidden  = true;
}

/** Opens the source picker when the footer "Import QR" button is clicked. */
function handleImportQR() {
  openImportSourceModal();
}

// ── Shared: parse → save → refresh ────────────────────

/**
 * Parses an otpauth:// URI, saves the resulting account, and refreshes the UI.
 * Shows an error toast if the URI is malformed.
 *
 * @param {string}  uri
 * @param {string}  [group] - Profile/group to assign to imported accounts.
 */
async function processOtpAuthURI(uri, group) {
  const { parseOtpAuthURI, parseMigrationURI } = await getQrImport();

  // Google Authenticator export — one QR, multiple accounts
  if (uri.toLowerCase().startsWith('otpauth-migration://')) {
    let parsed;
    try {
      parsed = parseMigrationURI(uri);
    } catch (err) {
      console.error('[DeskAuth] processOtpAuthURI (migration):', err);
      showToast(err instanceof Error ? err.message : t('toast_invalid_migration'), 'error');
      return;
    }

    if (parsed.length === 0) {
      showToast(t('toast_no_totp'), 'error');
      return;
    }

    for (const account of parsed) {
      await saveAccount({
        issuer:    account.issuer,
        name:      account.name,
        secret:    account.secret,
        period:    account.period,
        digits:    account.digits,
        algorithm: account.algorithm,
        ...(group && { group }),
      });
    }

    accounts = await getAccounts();
    renderAccounts();
    refreshAllCodes();

    const n = parsed.length;
    showToast(n === 1 ? t('toast_imported_1', String(n)) : t('toast_imported_n', String(n)), 'success');
    return;
  }

  // Standard otpauth:// — single account
  let parsed;
  try {
    parsed = parseOtpAuthURI(uri);
  } catch (err) {
    console.error('[DeskAuth] processOtpAuthURI:', err);
    showToast(err instanceof Error ? err.message : t('toast_invalid_qr'), 'error');
    return;
  }

  await saveAccount({
    issuer:    parsed.issuer,
    name:      parsed.name,
    secret:    parsed.secret,
    period:    parsed.period,
    digits:    parsed.digits,
    algorithm: parsed.algorithm,
    ...(group && { group }),
  });

  accounts = await getAccounts();
  renderAccounts();
  refreshAllCodes();

  const label = parsed.issuer
    ? `${parsed.issuer} (${parsed.name})`
    : parsed.name;
  showToast(t('toast_imported_1', label), 'success');
}

// ── Image file picker ──────────────────────────────────

/**
 * Opens a hidden file-picker limited to image files.
 * Resolves with the selected File, or null if the user cancels.
 *
 * @returns {Promise<File|null>}
 */
function pickImageFile() {
  return new Promise((resolve) => {
    const input = document.createElement('input');
    input.type   = 'file';
    input.accept = 'image/*';

    input.addEventListener('change', () => {
      resolve(input.files?.[0] ?? null);
      input.remove();
    });

    // Fallback for browsers that don't fire 'change' on cancel:
    // if window regains focus with no file selected, treat it as cancellation.
    window.addEventListener(
      'focus',
      () => setTimeout(() => { if (!input.files?.length) resolve(null); input.remove(); }, 300),
      { once: true }
    );

    input.style.display = 'none';
    document.body.appendChild(input);
    input.click();
  });
}

/** Handles "Choose Image" — file picker → decode → parse → save. */
async function handleImportFromFile() {
  const group = validateImportGroup();
  if (!group) return;
  closeImportSourceModal();

  const file = await pickImageFile();
  if (!file) return;

  elBtnImportQR.disabled = true;
  try {
    const { decodeQRFromImage } = await getQrImport();
    let uri;
    try {
      uri = await decodeQRFromImage(file);
    } catch (err) {
      console.error('[DeskAuth] handleImportFromFile: decode error:', err);
      showToast(t('toast_image_failed'), 'error');
      return;
    }

    if (!uri) {
      showToast(t('toast_no_qr'), 'error');
      return;
    }

    await processOtpAuthURI(uri, group);
  } finally {
    elBtnImportQR.disabled = false;
  }
}

// ── Camera scanner ─────────────────────────────────────

/**
 * Returns platform-appropriate steps to fix a blocked camera permission.
 * Detects macOS / Windows / Linux via navigator.userAgent.
 *
 * @returns {string[]} HTML strings for each <li> step.
 */
function getCameraPermissionSteps() {
  const ua = navigator.userAgent;

  if (ua.includes('Mac OS X') || ua.includes('Macintosh')) {
    return [
      t('mac_cam_step1_html'),
      t('mac_cam_step2_html'),
      t('mac_cam_step3_html'),
    ];
  }

  if (ua.includes('Windows')) {
    return [
      t('win_cam_step1_html'),
      t('win_cam_step2_html'),
      t('win_cam_step3_html'),
    ];
  }

  // Linux
  return [
    t('linux_cam_step1'),
    t('linux_cam_step2_html'),
    t('linux_cam_step3'),
  ];
}

/** @type {MediaStream|null} */
let _cameraStream = null;

/** @type {number|null} */
let _cameraRaf = null;

/** Stops the camera stream and hides the scanner modal. */
function closeCameraScanner() {
  if (_cameraRaf !== null) { cancelAnimationFrame(_cameraRaf); _cameraRaf = null; }
  if (_cameraStream)       { _cameraStream.getTracks().forEach((t) => t.stop()); _cameraStream = null; }
  elCameraVideo.srcObject = null;
  elModalCamera.hidden    = true;
}

/** Handles "Scan with Camera" — opens a dedicated tab for camera scanning. */
function handleImportFromCamera() {
  const group = validateImportGroup();
  if (!group) return;
  closeImportSourceModal();
  // Camera scanning runs in a full tab so getUserMedia permission dialogs
  // are displayed correctly (popup pages interfere with permission prompts).
  const url = new URL(chrome.runtime.getURL('camera.html'));
  if (group) url.searchParams.set('group', group);
  chrome.tabs.create({ url: url.toString() });
}

// ── Event listeners ────────────────────────────────────

elProfileSelect.addEventListener('change', () => {
  activeGroup  = elProfileSelect.value;
  searchQuery  = '';
  elSearchInput.value = '';
  renderAccounts();
  refreshAllCodes();
});

elSearchInput.addEventListener('input', () => {
  searchQuery = elSearchInput.value;
  filterCards();
});

elBtnAddAccount.addEventListener('click', openAddModal);
elBtnImportQR.addEventListener('click', handleImportQR);

elBtnCancel.addEventListener('click', closeAddModal);
elBtnSave.addEventListener('click', handleSaveAccount);

elModal.querySelector('.modal__backdrop')
  ?.addEventListener('click', closeAddModal);

// Import source picker
elBtnImportFromFile.addEventListener('click', handleImportFromFile);
elBtnImportFromCamera.addEventListener('click', handleImportFromCamera);
elInputImportGroup.addEventListener('input', () => {
  elInputImportGroup.classList.remove('form-input--error');
  elImportGroupError.hidden = true;
});
elBtnImportSourceCancel.addEventListener('click', closeImportSourceModal);

document.getElementById('btn-open-chrome-camera-settings')
  ?.addEventListener('click', () => {
    chrome.tabs.create({ url: 'chrome://settings/content/camera' });
  });

elModalImportSource.querySelector('.modal__backdrop')
  ?.addEventListener('click', closeImportSourceModal);

// Organize profiles modal
elBtnOrganizeSave.addEventListener('click', handleOrganizeSave);
elBtnOrganizeCancel.addEventListener('click', () => { elModalOrganize.hidden = true; });
elModalOrganize.querySelector('.modal__backdrop')
  ?.addEventListener('click', () => { elModalOrganize.hidden = true; });

// Help modal
elBtnHelp.addEventListener('click', openHelp);
elBtnHelpClose.addEventListener('click', () => { elModalHelp.hidden = true; });
elModalHelp.querySelector('.modal__backdrop')
  ?.addEventListener('click', () => { elModalHelp.hidden = true; });

// Edit account modal
elBtnEditSave.addEventListener('click', handleEditSave);
elBtnEditCancel.addEventListener('click', () => { elModalEdit.hidden = true; });
elModalEdit.querySelector('.modal__backdrop')
  ?.addEventListener('click', () => { elModalEdit.hidden = true; });

// Confirm delete modal
elBtnConfirmDeleteOk.addEventListener('click', confirmDeleteAccount);
elBtnConfirmDeleteCancel.addEventListener('click', () => { elModalConfirmDelete.hidden = true; });
elModalConfirmDelete.querySelector('.modal__backdrop')
  ?.addEventListener('click', () => { elModalConfirmDelete.hidden = true; });

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') {
    if (!elModal.hidden)                  closeAddModal();
    if (!elModalEdit.hidden)              elModalEdit.hidden = true;
    if (!elModalHelp.hidden)              elModalHelp.hidden = true;
    if (!elModalOrganize.hidden)          elModalOrganize.hidden = true;
    if (!elModalImportSource.hidden)      closeImportSourceModal();
    if (!elModalCamera.hidden)            closeCameraScanner();
    if (!elModalConfirmDelete.hidden)     elModalConfirmDelete.hidden = true;
  }
  if (e.key === 'Enter' && !elModal.hidden)     handleSaveAccount();
  if (e.key === 'Enter' && !elModalEdit.hidden) handleEditSave();
});

// ── Formatting helpers ─────────────────────────────────

/**
 * Inserts a space at the midpoint of a numeric OTP code for readability.
 * Non-numeric sentinels ('INVALID', '······') are returned unchanged.
 *
 * @param {string} code   - Raw OTP string.
 * @param {number} digits - Expected digit count (0 = passthrough).
 * @returns {string}
 */
function formatCode(code, digits) {
  if (!digits || !/^\d+$/.test(code)) return code;
  const mid = Math.floor(digits / 2);
  return `${code.slice(0, mid)} ${code.slice(mid)}`;
}

/**
 * Escapes HTML special characters for safe innerHTML insertion.
 *
 * @param {string} str
 * @returns {string}
 */
function escHtml(str) {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// ── Bootstrap ──────────────────────────────────────────

init();
