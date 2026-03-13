/**
 * DeskAuth - 2FA Authenticator for your Desktop
 * Developed by Weslley Harakawa
 * https://weslley.harakawa.tech
 *
 * qr-import.js — QR code decoding and otpauth:// URI parsing.
 *
 * Exports:
 *   decodeQRFromImage(file)  — Decodes a QR code from a user-selected File object.
 *   parseOtpAuthURI(uri)     — Parses an otpauth:// URI into structured account data.
 *   scanFrameForQR(videoEl)  — Decodes one frame from a live HTMLVideoElement (rAF loop).
 *
 * QR decoding uses the bundled jsQR library (MIT, vendor/jsqr.js).
 * No network calls are made at any point — everything runs offline.
 *
 * Supported URI format (Google Authenticator Key URI Format):
 *   otpauth://totp/<label>?secret=<base32>&issuer=<name>&algorithm=<algo>&digits=<n>&period=<p>
 *
 * References:
 *   https://github.com/google/google-authenticator/wiki/Key-Uri-Format
 *   https://datatracker.ietf.org/doc/html/rfc4648  (Base32 alphabet)
 *   https://github.com/cozmo/jsQR                  (jsQR library)
 */

import jsQR from './vendor/jsqr.js';
import { normaliseBase32, isValidBase32 } from './utils.js';

// ── Types (JSDoc) ─────────────────────────────────────

/**
 * @typedef {Object} OtpAuthParams
 * @property {'totp'}  type      - Always 'totp' (HOTP is not supported).
 * @property {string}  issuer    - Service name (e.g. "GitHub"). May be ''.
 * @property {string}  name      - Account label (e.g. "alice@example.com").
 * @property {string}  secret    - Normalised Base32 TOTP secret (no padding).
 * @property {string}  algorithm - Normalised HMAC algorithm ('SHA-1', 'SHA-256', 'SHA-512').
 * @property {number}  digits    - OTP length (typically 6).
 * @property {number}  period    - Time-step in seconds (typically 30).
 */

// ── Public API ────────────────────────────────────────

/**
 * Decodes a QR code from a user-selected image File.
 *
 * Flow:
 *  1. Read the File with FileReader (→ data URL).
 *  2. Load into a hidden HTMLImageElement.
 *  3. Draw onto an off-screen HTMLCanvasElement.
 *  4. Extract ImageData and pass to jsQR.
 *  5. Return the decoded string, or null if no QR code was found.
 *
 * @param  {File}             file - Image file selected by the user.
 * @returns {Promise<string|null>}  - Decoded QR content, or null.
 * @throws  {Error}                 - If the image cannot be loaded or decoded.
 */
export async function decodeQRFromImage(file) {
  if (!(file instanceof File)) {
    throw new Error('decodeQRFromImage: argument must be a File');
  }

  const imageData = await fileToImageData(file);

  // jsQR attempts to find a QR code in the pixel data.
  // 'attemptBoth' tries normal and inverted QR codes — handles screenshots
  // from apps with dark or light backgrounds without extra cost on success.
  const result = jsQR(
    imageData.data,
    imageData.width,
    imageData.height,
    { inversionAttempts: 'attemptBoth' }
  );

  return result ? result.data : null;
}

/**
 * Parses a raw otpauth:// URI string into a structured OtpAuthParams object.
 *
 * Handles both percent-encoded and unencoded labels.
 * Issuer is resolved by preference: query param > label prefix.
 * Defaults are applied for missing optional parameters.
 *
 * @param  {string}       uri - Raw URI string from a QR code or user input.
 * @returns {OtpAuthParams}
 * @throws  {Error}           - If the URI is malformed or missing required fields.
 */
export function parseOtpAuthURI(uri) {
  if (!uri || typeof uri !== 'string') {
    throw new Error('parseOtpAuthURI: URI must be a non-empty string');
  }

  // ── Scheme check ──────────────────────────────────────────────────────────
  if (!uri.toLowerCase().startsWith('otpauth://')) {
    throw new Error('parseOtpAuthURI: URI must begin with "otpauth://"');
  }

  // Strip "otpauth://" → "totp/label?params"
  const body = uri.slice('otpauth://'.length);

  // ── Type (TOTP / HOTP) ────────────────────────────────────────────────────
  const firstSlash = body.indexOf('/');
  if (firstSlash === -1) {
    throw new Error('parseOtpAuthURI: missing type segment');
  }

  const type = body.slice(0, firstSlash).toLowerCase();
  if (type !== 'totp') {
    throw new Error(
      `parseOtpAuthURI: unsupported type "${type}" — only "totp" is supported`
    );
  }

  const afterType = body.slice(firstSlash + 1); // "label?params" or "label"

  // ── Label and query string ────────────────────────────────────────────────
  const qMark    = afterType.indexOf('?');
  const rawLabel = qMark === -1 ? afterType       : afterType.slice(0, qMark);
  const rawQuery = qMark === -1 ? ''               : afterType.slice(qMark + 1);

  // Decode the label (may be percent-encoded)
  let label = '';
  try {
    label = decodeURIComponent(rawLabel).trim();
  } catch {
    throw new Error('parseOtpAuthURI: malformed percent-encoding in label');
  }

  // ── Label: split "Issuer:AccountName" ────────────────────────────────────
  // Only split on the FIRST colon — account names may contain colons.
  let labelIssuer = '';
  let labelName   = label;
  const colonIdx = label.indexOf(':');
  if (colonIdx !== -1) {
    labelIssuer = label.slice(0, colonIdx).trim();
    labelName   = label.slice(colonIdx + 1).trim();
  }

  // ── Query parameters (manual parse to avoid URL API edge cases) ───────────
  const params = parseQueryString(rawQuery);

  // ── secret (required) ─────────────────────────────────────────────────────
  const rawSecret = params.get('secret') ?? '';
  const secret    = normaliseBase32(rawSecret);

  if (!secret) {
    throw new Error('parseOtpAuthURI: "secret" parameter is missing or empty');
  }
  if (!isValidBase32(secret)) {
    throw new Error('parseOtpAuthURI: "secret" is not a valid Base32 string');
  }

  // ── issuer (optional, query param takes precedence over label prefix) ──────
  // Per the spec: if both are present and differ, use the query param value.
  const issuer = (params.get('issuer') ?? labelIssuer).trim();

  // ── name (account label) ──────────────────────────────────────────────────
  const name = labelName || issuer || 'Unknown Account';

  // ── algorithm (optional, default: SHA-1) ─────────────────────────────────
  const algorithm = normaliseAlgorithm(params.get('algorithm') ?? 'SHA1');

  // ── digits (optional, default: 6) ────────────────────────────────────────
  const rawDigits = params.get('digits') ?? '6';
  const digits    = parseInt(rawDigits, 10);
  if (!Number.isInteger(digits) || digits < 1 || digits > 10) {
    throw new Error(`parseOtpAuthURI: invalid "digits" value "${rawDigits}"`);
  }

  // ── period (optional, default: 30) ───────────────────────────────────────
  const rawPeriod = params.get('period') ?? '30';
  const period    = parseInt(rawPeriod, 10);
  if (!Number.isInteger(period) || period < 1 || period > 300) {
    throw new Error(`parseOtpAuthURI: invalid "period" value "${rawPeriod}"`);
  }

  return {
    type: 'totp',
    issuer,
    name,
    secret,
    algorithm,
    digits,
    period,
  };
}

/**
 * Attempts to decode a QR code from a single frame of a playing video element.
 *
 * Designed to be called inside a `requestAnimationFrame` loop. Returns null if
 * the video is not yet ready or if no QR code is detected in the current frame.
 *
 * @param  {HTMLVideoElement} videoEl - A playing video element (readyState >= HAVE_ENOUGH_DATA).
 * @returns {string|null} Decoded QR content, or null.
 */
export function scanFrameForQR(videoEl) {
  if (videoEl.readyState < videoEl.HAVE_ENOUGH_DATA) return null;

  const w = videoEl.videoWidth;
  const h = videoEl.videoHeight;
  if (w === 0 || h === 0) return null;

  const canvas = document.createElement('canvas');
  canvas.width  = w;
  canvas.height = h;

  // willReadFrequently avoids GPU round-trips on repeated getImageData calls
  const ctx = /** @type {CanvasRenderingContext2D} */ (
    canvas.getContext('2d', { willReadFrequently: true })
  );
  if (!ctx) return null;

  ctx.drawImage(videoEl, 0, 0);
  const imageData = ctx.getImageData(0, 0, w, h);

  const result = jsQR(imageData.data, imageData.width, imageData.height, {
    inversionAttempts: 'attemptBoth',
  });

  return result ? result.data : null;
}

// ── Internal helpers ──────────────────────────────────

/**
 * Loads a File (PNG/JPG/etc.) into a canvas and returns its ImageData.
 *
 * Uses FileReader → HTMLImageElement → HTMLCanvasElement so this works
 * entirely within the extension popup context without any native APIs.
 *
 * @param  {File}            file
 * @returns {Promise<ImageData>}
 * @throws  {Error} If the file cannot be read or is not a valid image.
 */
function fileToImageData(file) {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();

    reader.onerror = () => reject(new Error('fileToImageData: failed to read file'));

    reader.onload = (readerEvent) => {
      const dataUrl = /** @type {string} */ (readerEvent.target?.result);
      if (!dataUrl) {
        reject(new Error('fileToImageData: FileReader returned empty result'));
        return;
      }

      const img = new Image();

      img.onerror = () =>
        reject(new Error('fileToImageData: image failed to load — may not be a valid image'));

      img.onload = () => {
        const { naturalWidth: w, naturalHeight: h } = img;

        if (w === 0 || h === 0) {
          reject(new Error('fileToImageData: image has zero dimensions'));
          return;
        }

        const canvas = document.createElement('canvas');
        canvas.width  = w;
        canvas.height = h;

        const ctx = canvas.getContext('2d');
        if (!ctx) {
          reject(new Error('fileToImageData: failed to get 2D canvas context'));
          return;
        }

        ctx.drawImage(img, 0, 0);

        try {
          resolve(ctx.getImageData(0, 0, w, h));
        } catch (err) {
          reject(
            new Error(`fileToImageData: getImageData failed — ${/** @type {Error} */ (err).message}`)
          );
        }
      };

      img.src = dataUrl;
    };

    reader.readAsDataURL(file);
  });
}

/**
 * Parses a query string into a Map<string, string> (keys lowercase).
 *
 * Uses manual parsing instead of URLSearchParams to avoid quirks with
 * non-standard URL schemes such as `otpauth://`.
 *
 * @param  {string} query - Raw query string (no leading '?').
 * @returns {Map<string, string>}
 */
function parseQueryString(query) {
  const map = new Map();
  if (!query) return map;

  for (const pair of query.split('&')) {
    const eqIdx = pair.indexOf('=');
    if (eqIdx === -1) continue;

    const key = pair.slice(0, eqIdx).toLowerCase().trim();
    const raw = pair.slice(eqIdx + 1);

    let value = raw;
    try {
      value = decodeURIComponent(raw);
    } catch {
      // If decoding fails, keep the raw encoded value
    }

    if (key) map.set(key, value);
  }

  return map;
}

// ── Migration URI (Google Authenticator export) ────────

/**
 * Encodes a Uint8Array of raw bytes as a Base32 string (RFC 4648, no padding).
 * Used to convert TOTP secret bytes extracted from migration QR protobuf.
 *
 * @param  {Uint8Array} bytes
 * @returns {string}
 */
function uint8ToBase32(bytes) {
  const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let result   = '';
  let buffer   = 0;
  let bitsLeft = 0;

  for (const byte of bytes) {
    buffer    = (buffer << 8) | byte;
    bitsLeft += 8;
    while (bitsLeft >= 5) {
      bitsLeft -= 5;
      result   += ALPHA[(buffer >> bitsLeft) & 0x1F];
    }
  }
  if (bitsLeft > 0) result += ALPHA[(buffer << (5 - bitsLeft)) & 0x1F];

  return result;
}

/**
 * Reads a protobuf varint from `bytes` starting at `offset`.
 *
 * @param  {Uint8Array} bytes
 * @param  {number}     offset
 * @returns {{ value: number, offset: number }}
 */
function readVarint(bytes, offset) {
  let result = 0;
  let shift  = 0;
  while (offset < bytes.length) {
    const byte = bytes[offset++];
    result |= (byte & 0x7F) << shift;
    shift  += 7;
    if ((byte & 0x80) === 0) break;
  }
  return { value: result, offset };
}

/**
 * Decodes a protobuf byte array into an array of field descriptors.
 * Supports wire types 0 (varint), 2 (length-delimited), 1 and 5 (skipped).
 *
 * @param  {Uint8Array} bytes
 * @returns {Array<{ fieldNumber: number, value?: number, data?: Uint8Array }>}
 */
function decodeProtobuf(bytes) {
  const fields = [];
  let offset = 0;

  while (offset < bytes.length) {
    const tag = readVarint(bytes, offset);
    if (tag.offset === offset) break; // guard against infinite loop
    offset = tag.offset;

    const fieldNumber = tag.value >>> 3;
    const wireType    = tag.value & 0x07;

    if (wireType === 0) {
      const val = readVarint(bytes, offset);
      offset = val.offset;
      fields.push({ fieldNumber, value: val.value });
    } else if (wireType === 2) {
      const len = readVarint(bytes, offset);
      offset = len.offset;
      fields.push({ fieldNumber, data: bytes.slice(offset, offset + len.value) });
      offset += len.value;
    } else if (wireType === 1) {
      offset += 8; // 64-bit — skip
    } else if (wireType === 5) {
      offset += 4; // 32-bit — skip
    } else {
      break; // unknown wire type
    }
  }

  return fields;
}

/**
 * Parses a Google Authenticator `otpauth-migration://` URI.
 *
 * Google Authenticator encodes multiple accounts into a single QR using a
 * protobuf-serialised payload (base64-encoded in the `data` query parameter).
 * This parser decodes it without any external library.
 *
 * @param  {string} uri
 * @returns {OtpAuthParams[]}
 * @throws  {Error} If the URI is malformed or the payload cannot be decoded.
 */
export function parseMigrationURI(uri) {
  if (!uri.toLowerCase().startsWith('otpauth-migration://')) {
    throw new Error('parseMigrationURI: URI must begin with "otpauth-migration://"');
  }

  const qMark = uri.indexOf('?');
  if (qMark === -1) throw new Error('parseMigrationURI: missing query parameters');

  const params  = parseQueryString(uri.slice(qMark + 1));
  const rawData = params.get('data');
  if (!rawData) throw new Error('parseMigrationURI: missing "data" parameter');

  let bytes;
  try {
    const bin = atob(rawData);
    bytes = Uint8Array.from({ length: bin.length }, (_, i) => bin.charCodeAt(i));
  } catch {
    throw new Error('parseMigrationURI: "data" is not valid base64');
  }

  const decoder    = new TextDecoder();
  const topFields  = decodeProtobuf(bytes);
  /** @type {OtpAuthParams[]} */
  const accounts   = [];

  for (const field of topFields) {
    if (field.fieldNumber !== 1 || !field.data) continue; // otp_parameters (field 1)

    const pf = decodeProtobuf(field.data);
    let secret    = '';
    let name      = '';
    let issuer    = '';
    let algorithm = /** @type {'SHA-1'|'SHA-256'|'SHA-512'} */ ('SHA-1');
    let digits    = 6;
    let otpType   = 0; // 1=HOTP, 2=TOTP

    for (const p of pf) {
      if      (p.fieldNumber === 1 && p.data)         secret    = uint8ToBase32(p.data);
      else if (p.fieldNumber === 2 && p.data)         name      = decoder.decode(p.data);
      else if (p.fieldNumber === 3 && p.data)         issuer    = decoder.decode(p.data);
      else if (p.fieldNumber === 4 && p.value != null)
        algorithm = p.value === 2 ? 'SHA-256' : p.value === 3 ? 'SHA-512' : 'SHA-1';
      else if (p.fieldNumber === 5 && p.value != null) digits  = p.value === 2 ? 8 : 6;
      else if (p.fieldNumber === 6 && p.value != null) otpType = p.value;
    }

    if (!secret || otpType === 1) continue; // skip HOTP or accounts without a secret

    accounts.push({
      type:      'totp',
      issuer,
      name:      name || issuer || 'Unknown Account',
      secret,
      algorithm,
      digits,
      period:    30,
    });
  }

  return accounts;
}

// ──────────────────────────────────────────────────────

/**
 * Normalises an algorithm identifier to the format expected by Web Crypto.
 *
 * Accepts:   SHA1, SHA-1, sha1, SHA256, SHA-256, SHA512, SHA-512
 * Returns:   'SHA-1', 'SHA-256', or 'SHA-512'
 * Default:   'SHA-1' (for any unrecognised value)
 *
 * @param  {string} raw
 * @returns {'SHA-1' | 'SHA-256' | 'SHA-512'}
 */
function normaliseAlgorithm(raw) {
  // Strip dashes and spaces, then uppercase for uniform comparison
  switch (raw.trim().toUpperCase().replace(/-/g, '')) {
    case 'SHA1':   return 'SHA-1';
    case 'SHA256': return 'SHA-256';
    case 'SHA512': return 'SHA-512';
    default:
      console.warn(`[DeskAuth] qr-import: unknown algorithm "${raw}" — defaulting to SHA-1`);
      return 'SHA-1';
  }
}
