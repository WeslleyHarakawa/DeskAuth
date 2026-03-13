/**
 * DeskAuth - 2FA Authenticator for your Desktop
 * Developed by Weslley Harakawa
 * https://weslley.harakawa.tech
 *
 * storage.js — Account persistence via chrome.storage.local.
 *
 * ── Responsibility boundary ───────────────────────────────────────────────
 *
 *  This module owns the CRUD layer for TOTP accounts. It never stores
 *  plaintext secrets. All secrets flow through crypto.js:
 *    - encryptSecret() before any write to chrome.storage.local
 *    - decryptSecret() after any read from chrome.storage.local
 *
 * ── Storage layout ────────────────────────────────────────────────────────
 *
 *  chrome.storage.local key  │  value
 *  ─────────────────────────┼──────────────────────────────────────────────
 *  'deskauth_accounts'       │  JSON array of StoredAccount objects
 *  'deskauth_ikm'            │  (managed by crypto.js — do not touch here)
 *  'deskauth_salt'           │  (managed by crypto.js — do not touch here)
 *
 * ── Write-path efficiency ─────────────────────────────────────────────────
 *
 *  saveAccount and deleteAccount operate directly on the raw StoredAccount
 *  array (no decryption needed) and only encrypt/touch the new record.
 *  This means existing account blobs are never unnecessarily re-encrypted.
 *
 * ── Backward compatibility ────────────────────────────────────────────────
 *
 *  Accounts saved before encryption was implemented have a plaintext
 *  Base32 string in `encryptedSecret` instead of a JSON payload.
 *  decryptSecret() in crypto.js detects this automatically and returns the
 *  raw string with a console warning. The account remains usable; the secret
 *  is re-encrypted the next time that account is part of a full re-save
 *  (e.g. via setAccounts / importFromQR flow).
 */

import { encryptSecret, decryptSecret } from './crypto.js';
import { generateId }                   from './utils.js';

// ── Types (JSDoc) ─────────────────────────────────────

/**
 * @typedef {Object} Account
 * An account as it exists in memory. `secret` is always plaintext here.
 *
 * @property {string}  id          - UUID v4 — unique per account.
 * @property {string}  issuer      - Service label (e.g. "GitHub"). May be ''.
 * @property {string}  name        - User label (e.g. "user@example.com").
 * @property {string}  secret      - Base32 TOTP secret (plaintext — memory only).
 * @property {number}  addedAt     - Unix timestamp (ms) when added.
 * @property {number}  [period]    - TOTP period in seconds. Default: 30.
 * @property {number}  [digits]    - OTP digit count. Default: 6.
 * @property {string}  [algorithm] - HMAC algorithm. Default: 'SHA-1'.
 * @property {string}  [group]     - Profile/group label. Default: none.
 */

/**
 * @typedef {Object} StoredAccount
 * Shape persisted to chrome.storage.local. `encryptedSecret` is always the
 * JSON payload produced by encryptSecret() — never a plaintext Base32 string
 * (except in legacy records written before encryption was implemented).
 *
 * @property {string}  id               - UUID v4.
 * @property {string}  issuer           - Service label.
 * @property {string}  name             - User label.
 * @property {string}  encryptedSecret  - AES-GCM encrypted payload (JSON string).
 * @property {number}  addedAt          - Unix timestamp (ms).
 * @property {number}  [period]         - TOTP period.
 * @property {number}  [digits]         - OTP digit count.
 * @property {string}  [algorithm]      - HMAC algorithm.
 * @property {string}  [group]          - Profile/group label.
 */

// ── Storage keys ──────────────────────────────────────

const STORAGE_KEY = 'deskauth_accounts';

// ── Public API ────────────────────────────────────────

/**
 * Returns all stored accounts with plaintext secrets decrypted.
 *
 * Decryption is performed concurrently (Promise.all) to minimise latency
 * when many accounts are stored.
 *
 * If an individual account fails to decrypt (corrupted data, key mismatch),
 * it is returned with `secret = ''` so the popup can still render the card
 * and display 'INVALID' for that account's code without crashing.
 *
 * @returns {Promise<Account[]>}
 */
export async function getAccounts() {
  const stored = await readRawAccounts();

  const accounts = await Promise.all(
    stored.map(async (entry) => {
      let secret = '';
      try {
        secret = await decryptSecret(entry.encryptedSecret);
      } catch (err) {
        console.error(
          `[DeskAuth] storage: failed to decrypt account "${entry.name}" (${entry.id}):`, err
        );
        // secret stays '' — generateTOTP('') → 'INVALID' (safe UI fallback)
      }

      return {
        id:        entry.id,
        issuer:    entry.issuer,
        name:      entry.name,
        secret,
        addedAt:   entry.addedAt,
        period:    entry.period,
        digits:    entry.digits,
        algorithm: entry.algorithm,
        group:     entry.group,
      };
    })
  );

  return accounts;
}

/**
 * Saves a new account.
 *
 * Reads the raw stored array, appends a new encrypted entry, and writes
 * back. Existing records are never decrypted or re-encrypted during this
 * operation — only the new secret is encrypted.
 *
 * @param  {{ issuer?: string, name: string, secret: string,
 *             period?: number, digits?: number, algorithm?: string, group?: string }} newAccount
 * @returns {Promise<Account>} The saved account with its assigned ID.
 */
export async function saveAccount(newAccount) {
  // Encrypt only the new secret — do not touch existing records
  const encryptedSecret = await encryptSecret(newAccount.secret);

  /** @type {StoredAccount} */
  const entry = {
    id:              generateId(),
    issuer:          newAccount.issuer    ?? '',
    name:            newAccount.name,
    encryptedSecret,
    addedAt:         Date.now(),
    ...(newAccount.period    !== undefined && { period:    newAccount.period    }),
    ...(newAccount.digits    !== undefined && { digits:    newAccount.digits    }),
    ...(newAccount.algorithm !== undefined && { algorithm: newAccount.algorithm }),
    ...(newAccount.group     !== undefined && newAccount.group !== '' && { group: newAccount.group }),
  };

  const existing = await readRawAccounts();
  await chromeSet({ [STORAGE_KEY]: [...existing, entry] });

  // Return the in-memory representation (secret decrypted for caller's use)
  return {
    id:        entry.id,
    issuer:    entry.issuer,
    name:      entry.name,
    secret:    newAccount.secret,
    addedAt:   entry.addedAt,
    period:    entry.period,
    digits:    entry.digits,
    algorithm: entry.algorithm,
    group:     entry.group,
  };
}

/**
 * Deletes an account by ID.
 *
 * Reads the raw stored array and filters without decrypting — efficient
 * regardless of the number of accounts.
 *
 * @param  {string} id
 * @returns {Promise<void>}
 */
export async function deleteAccount(id) {
  const existing = await readRawAccounts();
  const updated  = existing.filter((a) => a.id !== id);
  await chromeSet({ [STORAGE_KEY]: updated });
}

/**
 * Updates non-secret fields (issuer, name, group) of an existing account.
 * The encrypted secret is never touched.
 *
 * @param  {string} id
 * @param  {{ issuer?: string, name?: string, group?: string }} changes
 * @returns {Promise<void>}
 */
export async function updateAccount(id, changes) {
  const existing = await readRawAccounts();
  const updated  = existing.map((a) => {
    if (a.id !== id) return a;
    const patch = {};
    if (changes.issuer !== undefined) patch.issuer = changes.issuer;
    if (changes.name   !== undefined) patch.name   = changes.name;
    if (changes.group  !== undefined) {
      if (changes.group) patch.group = changes.group;
      else               delete a.group; // clear group
    }
    return { ...a, ...patch };
  });
  await chromeSet({ [STORAGE_KEY]: updated });
}

/**
 * Replaces the entire account list (used by QR import and restore flows).
 *
 * All secrets are encrypted concurrently before writing.
 *
 * @param  {Account[]} accounts
 * @returns {Promise<void>}
 */
export async function setAccounts(accounts) {
  const stored = await Promise.all(accounts.map(toStoredAccount));
  await chromeSet({ [STORAGE_KEY]: stored });
}

/**
 * Erases all stored accounts. Irreversible — use with caution.
 *
 * @returns {Promise<void>}
 */
export async function clearAccounts() {
  await chromeRemove(STORAGE_KEY);
}

// ── Internal helpers ──────────────────────────────────

/**
 * Reads the raw StoredAccount array without decryption.
 * Used by the write-path operations to avoid unnecessary crypto work.
 *
 * @returns {Promise<StoredAccount[]>}
 */
async function readRawAccounts() {
  const data = await chromeGet(STORAGE_KEY);
  return /** @type {StoredAccount[]} */ (data[STORAGE_KEY] ?? []);
}

/**
 * Converts an in-memory Account to a StoredAccount by encrypting the secret.
 *
 * @param  {Account} account
 * @returns {Promise<StoredAccount>}
 */
async function toStoredAccount(account) {
  const encryptedSecret = await encryptSecret(account.secret);
  return {
    id:              account.id,
    issuer:          account.issuer,
    name:            account.name,
    encryptedSecret,
    addedAt:         account.addedAt,
    ...(account.period    !== undefined && { period:    account.period    }),
    ...(account.digits    !== undefined && { digits:    account.digits    }),
    ...(account.algorithm !== undefined && { algorithm: account.algorithm }),
  };
}

// ── chrome.storage wrappers (promisified) ─────────────

/**
 * @param {string | string[]} keys
 * @returns {Promise<Record<string, unknown>>}
 */
function chromeGet(keys) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(keys, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve(result);
      }
    });
  });
}

/**
 * @param {Record<string, unknown>} items
 * @returns {Promise<void>}
 */
function chromeSet(items) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(items, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve();
      }
    });
  });
}

/**
 * @param {string | string[]} keys
 * @returns {Promise<void>}
 */
function chromeRemove(keys) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.remove(keys, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
      } else {
        resolve();
      }
    });
  });
}
