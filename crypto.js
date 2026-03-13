/**
 * DeskAuth - 2FA Authenticator for your Desktop
 * Developed by Weslley Harakawa
 * https://weslley.harakawa.tech
 *
 * crypto.js — AES-256-GCM local encryption for TOTP secrets.
 *
 * All cryptographic operations use the Web Crypto API exclusively.
 * No external libraries. No network calls. Fully offline.
 *
 * ── Security model (MVP) ───────────────────────────────────────────────────
 *
 *  Key derivation:
 *   1. On first run, 32 cryptographically random bytes are generated as
 *      Installation Key Material (IKM) and stored in chrome.storage.local
 *      under STORAGE_KEY_IKM.
 *   2. A separate 16-byte PBKDF2 salt is generated and stored under
 *      STORAGE_KEY_SALT.
 *   3. PBKDF2(IKM, salt, 310 000 iterations, SHA-256) derives the
 *      AES-256-GCM working key. The resulting CryptoKey is non-extractable —
 *      it lives only inside the Web Crypto subsystem and cannot be read back
 *      as raw bytes.
 *   4. The derived CryptoKey is cached in memory (_keyCache) for the lifetime
 *      of the popup, so the 310k PBKDF2 iterations run at most once per
 *      popup session (~150–300 ms on typical hardware).
 *
 *  Per-encryption randomness:
 *   5. Every call to encryptSecret() generates a fresh 12-byte random IV
 *      via crypto.getRandomValues(). The same plaintext encrypted twice
 *      produces different ciphertext each time.
 *
 *  AES-GCM authentication:
 *   6. AES-GCM provides authenticated encryption — any tampering with the
 *      ciphertext or IV causes decryption to throw, which the callers catch.
 *
 * ── MVP security limitations ───────────────────────────────────────────────
 *
 *  The IKM is stored in chrome.storage.local alongside the encrypted blobs.
 *  An attacker who obtains a full copy of the Chrome profile directory (e.g.
 *  via physical access or malware with filesystem read rights) can read both
 *  the IKM and the ciphertext and decrypt offline.
 *
 *  This scheme protects against:
 *   (a) Casual inspection: secrets are not visible as plaintext in DevTools
 *       → Application → Storage → chrome.storage.local
 *   (b) Naive data export: copying only the extension storage values without
 *       knowing the derivation procedure does not yield readable secrets.
 *   (c) Cross-extension contamination: chrome.storage.local is sandboxed per
 *       extension; other extensions cannot read DeskAuth's storage.
 *
 * ── Upgrade path ──────────────────────────────────────────────────────────
 *
 *  The payload carries a version field ("v") so the format can evolve.
 *  A future "v2" could replace IKM-derived keys with a user master password:
 *    - Remove IKM from storage
 *    - Derive key from PBKDF2(masterPassword, salt)
 *    - Prompt on popup open when key is not cached
 *  The encrypt / decrypt API surface stays identical — only getOrCreateKey()
 *  changes internally.
 *
 * ── Encrypted payload format (version 1) ──────────────────────────────────
 *
 *  JSON string stored as the value of `encryptedSecret` in each account record:
 *
 *    { "v": 1, "iv": "<base64url, 16 chars>", "ct": "<base64url, variable>" }
 *
 *  `iv` — 12-byte AES-GCM initialisation vector, base64url-encoded (no padding)
 *  `ct` — AES-GCM ciphertext + 16-byte auth tag, base64url-encoded (no padding)
 */

// ── Crypto constants ──────────────────────────────────

/** AES-GCM key size in bits. */
export const AES_KEY_LENGTH = 256;

/** AES-GCM IV size in bytes. NIST recommends 96-bit (12-byte) for GCM. */
export const GCM_IV_LENGTH = 12;

/**
 * PBKDF2 iteration count.
 * OWASP 2023 recommendation for PBKDF2-HMAC-SHA256 is 600 000; we use
 * 310 000 as a balance between security and popup startup latency.
 * Increase this in a future version once a loading indicator is in place.
 */
export const PBKDF2_ITERATIONS = 310_000;

/** Encrypted payload schema version embedded in every stored blob. */
const PAYLOAD_VERSION = 1;

// ── chrome.storage keys used exclusively by crypto.js ─

/**
 * Stores the base64url-encoded 32-byte Installation Key Material (IKM).
 * Generated once on first use; never changes for the life of the installation.
 */
const STORAGE_KEY_IKM  = 'deskauth_ikm';

/**
 * Stores the base64url-encoded 16-byte PBKDF2 salt.
 * Generated once on first use alongside the IKM.
 */
const STORAGE_KEY_SALT = 'deskauth_salt';

// Kept for consumers that imported it from the old skeleton.
export const CIPHER_SEPARATOR = ':';

// ── Module-level key cache ────────────────────────────

/**
 * The derived AES-GCM CryptoKey, cached after the first derivation.
 * Null until getOrCreateKey() has been called at least once.
 *
 * @type {CryptoKey | null}
 */
let _keyCache = null;

// ── Public API ────────────────────────────────────────

/**
 * Encrypts a plaintext Base32 TOTP secret with AES-256-GCM.
 *
 * Returns a JSON string that is safe to store directly as the
 * `encryptedSecret` field of a StoredAccount.
 *
 * @param  {string} plaintext - Base32 TOTP secret (plaintext, in memory only).
 * @returns {Promise<string>} - JSON-encoded encrypted payload.
 * @throws {Error}            - If Web Crypto or chrome.storage fails.
 */
export async function encryptSecret(plaintext) {
  const key = await getOrCreateKey();

  // Fresh random IV for every encryption (prevents ciphertext reuse)
  const iv = new Uint8Array(GCM_IV_LENGTH);
  crypto.getRandomValues(iv);

  const data       = new TextEncoder().encode(plaintext);
  const cipherBuf  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  const ciphertext = new Uint8Array(cipherBuf);

  /** @type {{ v: number, iv: string, ct: string }} */
  const payload = {
    v:  PAYLOAD_VERSION,
    iv: toBase64url(iv),
    ct: toBase64url(ciphertext),
  };

  return JSON.stringify(payload);
}

/**
 * Decrypts an encrypted payload produced by encryptSecret().
 *
 * Backward-compatible: if `payload` is not a JSON object (i.e. it is a
 * legacy plaintext secret from before encryption was implemented), it is
 * returned as-is with a console warning so the UI keeps working.
 *
 * @param  {string} payload - JSON-encoded encrypted payload, or legacy plaintext.
 * @returns {Promise<string>} - Decrypted plaintext secret.
 * @throws {Error}           - If the payload is a recognised encrypted format
 *                             but decryption fails (tampered / corrupted data).
 */
export async function decryptSecret(payload) {
  // ── Backward-compatibility: detect legacy plaintext records ──────────────
  //
  // Before encryption was implemented, encryptedSecret held the raw Base32
  // secret. Those records do NOT start with '{', so we can distinguish them
  // reliably. We return them as-is and let storage.js schedule re-encryption
  // on next write. A console.warn keeps the risk visible in DevTools.
  if (!payload || typeof payload !== 'string') {
    throw new Error('decryptSecret: payload must be a non-empty string');
  }

  if (!payload.startsWith('{')) {
    console.warn(
      '[DeskAuth] crypto: legacy plaintext secret detected — ' +
      'will be re-encrypted on next account save.'
    );
    return payload; // safe passthrough for migration period
  }

  // ── Parse and validate the encrypted payload ─────────────────────────────
  let parsed;
  try {
    parsed = JSON.parse(payload);
  } catch {
    throw new Error('decryptSecret: payload is not valid JSON');
  }

  if (parsed.v !== PAYLOAD_VERSION) {
    throw new Error(`decryptSecret: unknown payload version ${parsed.v}`);
  }

  if (typeof parsed.iv !== 'string' || typeof parsed.ct !== 'string') {
    throw new Error('decryptSecret: payload missing "iv" or "ct" fields');
  }

  // ── Decrypt ───────────────────────────────────────────────────────────────
  const key        = await getOrCreateKey();
  const iv         = fromBase64url(parsed.iv);
  const ciphertext = fromBase64url(parsed.ct);

  // AES-GCM will throw a DOMException if authentication fails —
  // this catches tampered ciphertext, wrong key, or bit-flip errors.
  let plainBuf;
  try {
    plainBuf = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, ciphertext);
  } catch {
    throw new Error(
      'decryptSecret: AES-GCM authentication failed — data may be corrupted or tampered.'
    );
  }

  return new TextDecoder().decode(plainBuf);
}

/**
 * Clears the in-memory key cache.
 *
 * Call this only in test scenarios where you need to force a fresh key
 * derivation (e.g. to simulate a new installation). Not intended for
 * production use.
 */
export function resetKeyCache() {
  _keyCache = null;
}

// ── Internal: key management ──────────────────────────

/**
 * Returns the AES-256-GCM CryptoKey for this installation.
 *
 * On the first call:
 *  1. Loads (or generates) the 32-byte IKM from chrome.storage.local.
 *  2. Loads (or generates) the 16-byte PBKDF2 salt from chrome.storage.local.
 *  3. Runs PBKDF2(IKM, salt, 310 000, SHA-256) to derive a non-extractable
 *     AES-256-GCM CryptoKey.
 *  4. Caches the result in _keyCache.
 *
 * On subsequent calls within the same popup session, returns _keyCache
 * immediately without touching chrome.storage or running PBKDF2 again.
 *
 * @returns {Promise<CryptoKey>}
 */
async function getOrCreateKey() {
  if (_keyCache !== null) return _keyCache;

  // ── Step 1: Load or generate IKM and salt ────────────────────────────────
  const stored = await cryptoStorageGet([STORAGE_KEY_IKM, STORAGE_KEY_SALT]);

  let ikmB64  = /** @type {string|undefined} */ (stored[STORAGE_KEY_IKM]);
  let saltB64 = /** @type {string|undefined} */ (stored[STORAGE_KEY_SALT]);

  /** @type {Record<string, string>} */
  const toWrite = {};

  if (!ikmB64) {
    // First run: generate a fresh 32-byte Installation Key Material
    const ikmBytes = new Uint8Array(32);
    crypto.getRandomValues(ikmBytes);
    ikmB64 = toBase64url(ikmBytes);
    toWrite[STORAGE_KEY_IKM] = ikmB64;
  }

  if (!saltB64) {
    // First run: generate a fresh 16-byte PBKDF2 salt
    const saltBytes = new Uint8Array(16);
    crypto.getRandomValues(saltBytes);
    saltB64 = toBase64url(saltBytes);
    toWrite[STORAGE_KEY_SALT] = saltB64;
  }

  // Persist any newly generated values atomically before using them
  if (Object.keys(toWrite).length > 0) {
    await cryptoStorageSet(toWrite);
  }

  // ── Step 2: Import IKM as PBKDF2 base key ────────────────────────────────
  const ikmBytes = fromBase64url(ikmB64);

  const pbkdf2BaseKey = await crypto.subtle.importKey(
    'raw',
    ikmBytes,
    'PBKDF2',
    /* extractable */ false,
    ['deriveKey']
  );

  // ── Step 3: Derive the AES-256-GCM working key via PBKDF2 ────────────────
  const saltBytes = fromBase64url(saltB64);

  const aesKey = await crypto.subtle.deriveKey(
    {
      name:       'PBKDF2',
      salt:       saltBytes,
      iterations: PBKDF2_ITERATIONS,
      hash:       'SHA-256',
    },
    pbkdf2BaseKey,
    { name: 'AES-GCM', length: AES_KEY_LENGTH },
    /* extractable */ false,      // key bytes can never be read back
    ['encrypt', 'decrypt']
  );

  // ── Step 4: Cache and return ─────────────────────────────────────────────
  _keyCache = aesKey;
  return aesKey;
}

// ── Internal: base64url helpers ───────────────────────

/**
 * Encodes a Uint8Array to a base64url string (RFC 4648 § 5, no padding).
 *
 * Uses a loop instead of spread (`...bytes`) to avoid exceeding the
 * call-stack argument limit for very large arrays.
 *
 * @param  {Uint8Array} bytes
 * @returns {string}
 */
function toBase64url(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary)
    .replace(/\+/g, '-')   // RFC 4648 §5: + → -
    .replace(/\//g, '_')   //              / → _
    .replace(/=/g,  '');   // strip padding
}

/**
 * Decodes a base64url string (with or without padding) to a Uint8Array.
 *
 * @param  {string} b64url
 * @returns {Uint8Array}
 */
function fromBase64url(b64url) {
  // Restore standard base64 alphabet
  const std = b64url.replace(/-/g, '+').replace(/_/g, '/');
  // Re-add '=' padding to make length a multiple of 4
  const padded = std + '='.repeat((4 - (std.length % 4)) % 4);
  const binary = atob(padded);
  const bytes  = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ── Internal: chrome.storage wrappers ────────────────
//
// crypto.js manages its own storage keys (IKM, salt) independently of
// storage.js to avoid circular imports and keep the security layer isolated.

/**
 * @param {string[]} keys
 * @returns {Promise<Record<string, unknown>>}
 */
function cryptoStorageGet(keys) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.get(keys, (result) => {
      if (chrome.runtime.lastError) {
        reject(new Error(`[DeskAuth] crypto storage read failed: ${chrome.runtime.lastError.message}`));
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
function cryptoStorageSet(items) {
  return new Promise((resolve, reject) => {
    chrome.storage.local.set(items, () => {
      if (chrome.runtime.lastError) {
        reject(new Error(`[DeskAuth] crypto storage write failed: ${chrome.runtime.lastError.message}`));
      } else {
        resolve();
      }
    });
  });
}
