/**
 * DeskAuth - 2FA Authenticator for your Desktop
 * Developed by Weslley Harakawa
 * https://weslley.harakawa.tech
 *
 * totp.js — RFC 6238 TOTP / RFC 4226 HOTP engine.
 *
 * Fully implemented using the Web Crypto API — no external libraries.
 * Compatible with Google Authenticator, Aegis, Bitwarden, and all
 * standard otpauth:// TOTP issuers.
 *
 * Algorithm (RFC 6238 § 4):
 *   T  = floor(unix_epoch / period)              — time counter
 *   HS = HMAC-SHA1(secret_bytes, T_bytes)        — 20-byte digest
 *   OTP = DT(HS) mod 10^digits                   — dynamic truncation (RFC 4226 § 5.3)
 *
 * Supported algorithms (for future accounts):
 *   SHA-1   (default, most widely used)
 *   SHA-256 (supported by some issuers)
 *   SHA-512 (supported by some issuers)
 */

// ── Constants ──────────────────────────────────────────

/** Default TOTP time-step in seconds (RFC 6238 § 4). */
export const DEFAULT_PERIOD    = 30;

/** Default OTP digit count (RFC 4226 § 5.3). */
export const DEFAULT_DIGITS    = 6;

/** Default HMAC algorithm (RFC 6238 § 1.2). */
export const DEFAULT_ALGORITHM = 'SHA-1';

/**
 * Allowed HMAC algorithms mapped to their Web Crypto hash identifiers.
 * Structured so SHA-256 / SHA-512 can be used by adding accounts
 * that specify `algorithm` in their otpauth:// URI.
 *
 * @type {Record<string, string>}
 */
export const SUPPORTED_ALGORITHMS = {
  'SHA-1':   'SHA-1',
  'SHA-256': 'SHA-256',
  'SHA-512': 'SHA-512',
};

/** RFC 4648 Base32 alphabet (uppercase, A–Z then 2–7). */
const BASE32_CHARS = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

// ── Public API ─────────────────────────────────────────

/**
 * Decodes a Base32-encoded string to a Uint8Array.
 *
 * Follows RFC 4648 § 6: alphabet is A–Z (0–25) and 2–7 (26–31).
 * Padding ('=') is stripped and ignored.
 * Case-insensitive; whitespace is stripped.
 *
 * @param  {string} secret - Base32 string (with or without '=' padding).
 * @returns {Uint8Array}
 * @throws {Error} If the string contains characters outside the Base32 alphabet.
 */
export function base32ToBytes(secret) {
  // Normalize: strip whitespace, uppercase, strip padding
  const normalized = secret
    .trim()
    .toUpperCase()
    .replace(/\s+/g, '')
    .replace(/=+$/, '');

  if (normalized.length === 0) {
    throw new Error('base32ToBytes: empty secret');
  }

  // Validate alphabet before processing
  for (let i = 0; i < normalized.length; i++) {
    if (BASE32_CHARS.indexOf(normalized[i]) === -1) {
      throw new Error(
        `base32ToBytes: invalid character '${normalized[i]}' at position ${i}`
      );
    }
  }

  // Accumulate 5-bit values into an 8-bit byte stream
  const outputLength = Math.floor((normalized.length * 5) / 8);
  const bytes        = new Uint8Array(outputLength);

  let buffer   = 0; // bit accumulator
  let bitsLeft = 0; // how many valid bits are in `buffer`
  let byteIdx  = 0;

  for (let i = 0; i < normalized.length; i++) {
    const val = BASE32_CHARS.indexOf(normalized[i]); // 0–31 (5 bits)

    buffer    = (buffer << 5) | val;
    bitsLeft += 5;

    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      bytes[byteIdx++] = (buffer >>> bitsLeft) & 0xff;
    }
  }

  return bytes;
}

/**
 * Returns the current TOTP time-step counter.
 *
 * T = floor(unix_time_seconds / period)
 *
 * For the default 30-second period this increments every 30 seconds
 * in lock-step with Google Authenticator.
 *
 * @param  {number} [period=30] - Time-step length in seconds.
 * @returns {number}
 */
export function timeStep(period = DEFAULT_PERIOD) {
  return Math.floor(Date.now() / 1000 / period);
}

/**
 * Returns how many seconds remain until the current TOTP window expires.
 *
 * @param  {number} [period=30] - Time-step length in seconds.
 * @returns {number}            - Integer in [1, period].
 */
export function secondsRemaining(period = DEFAULT_PERIOD) {
  const epoch = Math.floor(Date.now() / 1000);
  const remaining = period - (epoch % period);
  // Clamp to [1, period]: remaining is always > 0 because epoch % period is in [0, period-1]
  return remaining;
}

/**
 * Encodes a non-negative integer counter into an 8-byte big-endian ArrayBuffer.
 *
 * RFC 4226 § 5.1 requires the counter as a 64-bit unsigned big-endian integer.
 * BigInt is used to handle the full 64-bit range without precision loss.
 *
 * @param  {number} counter - Non-negative integer (TOTP step or HOTP counter).
 * @returns {ArrayBuffer}   - 8 bytes, big-endian.
 */
export function counterToBuffer(counter) {
  const buf  = new ArrayBuffer(8);
  const view = new DataView(buf);

  // Split into two 32-bit halves using BigInt for precision across the full 64-bit range
  const big = BigInt(counter);
  view.setUint32(0, Number((big >> 32n) & 0xffffffffn), /* big-endian */ false);
  view.setUint32(4, Number(big & 0xffffffffn),           /* big-endian */ false);

  return buf;
}

/**
 * Generates an HOTP code for the given pre-decoded secret bytes and counter.
 *
 * Implements RFC 4226 § 5:
 *   Step 1 — HS  = HMAC-SHA1(key, counter_bytes)
 *   Step 2 — Snum = DT(HS) — dynamic truncation
 *   Step 3 — D   = Snum mod 10^Digit
 *
 * This is the cryptographic core; TOTP wraps it with a time-derived counter.
 *
 * @param  {Uint8Array} secretBytes         - Decoded secret key bytes.
 * @param  {number}     counter             - HOTP counter value.
 * @param  {number}     [digits=6]          - OTP length (typically 6 or 8).
 * @param  {string}     [algorithm='SHA-1'] - HMAC hash: 'SHA-1', 'SHA-256', or 'SHA-512'.
 * @returns {Promise<string>}               - Zero-padded OTP string.
 */
export async function generateHOTP(
  secretBytes,
  counter,
  digits    = DEFAULT_DIGITS,
  algorithm = DEFAULT_ALGORITHM
) {
  // Resolve algorithm to Web Crypto hash name
  const hashName = SUPPORTED_ALGORITHMS[algorithm];
  if (!hashName) {
    throw new Error(`generateHOTP: unsupported algorithm '${algorithm}'`);
  }

  // Import the raw secret bytes as an HMAC-{hash} CryptoKey
  const key = await crypto.subtle.importKey(
    'raw',
    secretBytes,
    { name: 'HMAC', hash: hashName },
    /* extractable */ false,
    ['sign']
  );

  // Sign the 8-byte big-endian counter buffer
  const counterBuf = counterToBuffer(counter);
  const signature  = await crypto.subtle.sign('HMAC', key, counterBuf);
  const hmac       = new Uint8Array(signature);

  // RFC 4226 § 5.3 — Dynamic Truncation
  return truncate(hmac, digits);
}

/**
 * Generates the current TOTP code for a Base32-encoded secret.
 *
 * This is the primary entry point used by the popup.
 * Catches all errors (invalid secret, Web Crypto failures) and returns
 * the sentinel string 'INVALID' so the UI degrades gracefully.
 *
 * @param  {string}  secret                   - Base32-encoded shared secret.
 * @param  {object}  [opts]
 * @param  {number}  [opts.period=30]          - Time-step in seconds.
 * @param  {number}  [opts.digits=6]           - OTP digit count.
 * @param  {string}  [opts.algorithm='SHA-1']  - HMAC hash algorithm.
 * @returns {Promise<string>}                  - OTP string or 'INVALID'.
 */
export async function generateTOTP(secret, {
  period    = DEFAULT_PERIOD,
  digits    = DEFAULT_DIGITS,
  algorithm = DEFAULT_ALGORITHM,
} = {}) {
  try {
    const secretBytes = base32ToBytes(secret);
    const counter     = timeStep(period);
    return await generateHOTP(secretBytes, counter, digits, algorithm);
  } catch (err) {
    console.error('[DeskAuth] generateTOTP failed:', err);
    return 'INVALID';
  }
}

// ── Internal helpers ───────────────────────────────────

/**
 * RFC 4226 § 5.3 — Dynamic Truncation.
 *
 * The offset is taken from the low nibble of the last HMAC byte,
 * which works correctly for SHA-1 (20 bytes), SHA-256 (32 bytes),
 * and SHA-512 (64 bytes).
 *
 *   offset  = hmac[len-1] & 0x0f
 *   binCode = (hmac[offset]   & 0x7f) << 24
 *           | (hmac[offset+1] & 0xff) << 16
 *           | (hmac[offset+2] & 0xff) <<  8
 *           | (hmac[offset+3] & 0xff)
 *   OTP     = binCode mod 10^digits, zero-padded
 *
 * @param  {Uint8Array} hmac   - Raw HMAC output bytes.
 * @param  {number}     digits - Desired OTP length.
 * @returns {string}           - Zero-padded numeric string.
 */
function truncate(hmac, digits) {
  // Use the last byte's low nibble as the byte offset into the digest
  const offset = hmac[hmac.length - 1] & 0x0f;

  // Extract 4 bytes starting at offset, masking the MSB of the first byte
  // (>>> 0 converts the signed 32-bit result to unsigned)
  const binCode = (
    ((hmac[offset]     & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) <<  8) |
     (hmac[offset + 3] & 0xff)
  ) >>> 0;

  const otp = binCode % (10 ** digits);
  return String(otp).padStart(digits, '0');
}

// ── Developer self-test ────────────────────────────────
//
// To run in the browser console:
//   (await import(chrome.runtime.getURL('totp.js'))).runSelfTest()
//
// Expected output (all PASS):
//
//   RFC 4226 HOTP vectors (secret = "12345678901234567890"):
//     counter 0 → 755224  ✓ PASS
//     counter 1 → 287082  ✓ PASS
//     ... (10 vectors)
//
//   RFC 6238 TOTP vectors (SHA-1, 8 digits):
//     T=59          → 94287082  ✓ PASS
//     T=1111111109  → 07081804  ✓ PASS
//     ... (6 vectors)
//
// RFC test secret: "12345678901234567890" (ASCII)
// Base32:          "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
//
// Source: RFC 4226 Appendix D, RFC 6238 Appendix B.

/**
 * Runs RFC 4226 / RFC 6238 test vectors and logs results to the console.
 *
 * @returns {Promise<boolean>} — true if all tests pass, false otherwise.
 */
export async function runSelfTest() {
  const SECRET_BASE32 = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  let secretBytes;

  try {
    secretBytes = base32ToBytes(SECRET_BASE32);
  } catch (e) {
    console.error('[DeskAuth] runSelfTest: base32ToBytes failed:', e);
    return false;
  }

  // ── RFC 4226 Appendix D — HOTP vectors (counter 0–9, 6 digits, SHA-1) ──
  const hotpVectors = [
    { counter: 0, expected: '755224' },
    { counter: 1, expected: '287082' },
    { counter: 2, expected: '359152' },
    { counter: 3, expected: '969429' },
    { counter: 4, expected: '338314' },
    { counter: 5, expected: '254676' },
    { counter: 6, expected: '287922' },
    { counter: 7, expected: '162583' },
    { counter: 8, expected: '399871' },
    { counter: 9, expected: '520489' },
  ];

  console.group('[DeskAuth] RFC 4226 HOTP test vectors (SHA-1, 6 digits)');
  let allPass = true;

  for (const { counter, expected } of hotpVectors) {
    const got  = await generateHOTP(secretBytes, counter, 6, 'SHA-1');
    const pass = got === expected;
    if (!pass) allPass = false;
    console.log(
      `  counter=${counter}  expected=${expected}  got=${got}  ${pass ? '✓ PASS' : '✗ FAIL'}`
    );
  }
  console.groupEnd();

  // ── RFC 6238 Appendix B — TOTP vectors (8 digits, SHA-1) ──
  // These use specific Unix timestamps, so we compute the counter directly.
  const totpVectors = [
    { unixTime: 59,          expected: '94287082' },
    { unixTime: 1111111109,  expected: '07081804' },
    { unixTime: 1111111111,  expected: '14050471' },
    { unixTime: 1234567890,  expected: '89005924' },
    { unixTime: 2000000000,  expected: '69279037' },
    { unixTime: 20000000000, expected: '65353130' },
  ];

  console.group('[DeskAuth] RFC 6238 TOTP test vectors (SHA-1, 8 digits, period=30)');

  for (const { unixTime, expected } of totpVectors) {
    const counter = Math.floor(unixTime / 30);
    const got     = await generateHOTP(secretBytes, counter, 8, 'SHA-1');
    const pass    = got === expected;
    if (!pass) allPass = false;
    console.log(
      `  T=${String(unixTime).padEnd(11)}  expected=${expected}  got=${got}  ${pass ? '✓ PASS' : '✗ FAIL'}`
    );
  }
  console.groupEnd();

  // ── Base32 edge-case validation ──
  console.group('[DeskAuth] base32ToBytes validation');

  const b32Cases = [
    { input: 'JBSWY3DPEHPK3PXP',  expectBytes: 16, label: 'standard (no padding)' },
    { input: 'jbswy3dpehpk3pxp',  expectBytes: 16, label: 'lowercase input'       },
    { input: 'JBSWY3DP========',  expectBytes: 5,  label: 'with = padding'        },
    { input: '  JBSWY3DP  ',      expectBytes: 5,  label: 'whitespace stripped'   },
  ];

  for (const { input, expectBytes, label } of b32Cases) {
    try {
      const bytes = base32ToBytes(input);
      const pass  = bytes.length === expectBytes;
      if (!pass) allPass = false;
      console.log(`  ${label}: ${bytes.length} bytes  ${pass ? '✓ PASS' : `✗ FAIL (expected ${expectBytes})`}`);
    } catch (e) {
      allPass = false;
      console.log(`  ${label}: ✗ FAIL (threw: ${e.message})`);
    }
  }

  // Should throw
  try {
    base32ToBytes('INVALID!@#$');
    allPass = false;
    console.log('  reject invalid chars: ✗ FAIL (did not throw)');
  } catch {
    console.log('  reject invalid chars: ✓ PASS');
  }

  console.groupEnd();

  console.log(`[DeskAuth] Self-test complete — ${allPass ? '✓ ALL PASS' : '✗ SOME FAILURES'}`);
  return allPass;
}
