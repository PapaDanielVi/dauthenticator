/**
 * RFC 4226 (HOTP) and RFC 6238 (TOTP) code generation on top of the native
 * Web Crypto API, plus the RFC 4648 Base32 codec used for OTP secrets.
 */
import type { AccountEntry, Digits, HashAlgorithm } from '../shared/types';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
const BASE32_LOOKUP: Record<string, number> = Object.fromEntries(
  Array.from(BASE32_ALPHABET, (char, index) => [char, index]),
);

export const DEFAULT_PERIOD = 30;
export const DEFAULT_DIGITS: Digits = 6;
export const DEFAULT_ALGORITHM: HashAlgorithm = 'SHA-1';
export const SUPPORTED_ALGORITHMS: readonly HashAlgorithm[] = ['SHA-1', 'SHA-256', 'SHA-512'];

/**
 * Normalizes user supplied Base32: removes whitespace, dashes and padding,
 * upper-cases letters. Does not validate.
 */
export function normalizeBase32(input: string): string {
  return input.replace(/[\s\-_=]/g, '').toUpperCase();
}

export function isValidBase32(input: string): boolean {
  const clean = normalizeBase32(input);
  if (clean.length === 0) {
    return false;
  }
  for (const char of clean) {
    if (!(char in BASE32_LOOKUP)) {
      return false;
    }
  }
  // Trailing partial bits are ignored (as most authenticators do), but at
  // least one whole byte of key material is required.
  return clean.length >= 2;
}

export function base32Decode(input: string): Uint8Array<ArrayBuffer> {
  const clean = normalizeBase32(input);
  if (!isValidBase32(clean)) {
    throw new Error('Secret is not valid Base32.');
  }
  const out = new Uint8Array(Math.floor((clean.length * 5) / 8));
  let buffer = 0;
  let bits = 0;
  let index = 0;
  for (const char of clean) {
    buffer = (buffer << 5) | (BASE32_LOOKUP[char] as number);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out[index] = (buffer >>> bits) & 0xff;
      index += 1;
    }
  }
  return out;
}

export function base32Encode(bytes: Uint8Array): string {
  let out = '';
  let buffer = 0;
  let bits = 0;
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += BASE32_ALPHABET[(buffer >>> bits) & 0x1f];
    }
  }
  if (bits > 0) {
    out += BASE32_ALPHABET[(buffer << (5 - bits)) & 0x1f];
  }
  return out;
}

/** Maps loose algorithm names ("sha1", "SHA256", "HmacSHA512") onto Web Crypto names. */
export function parseAlgorithm(value: unknown): HashAlgorithm | null {
  if (typeof value === 'number') {
    return null;
  }
  const clean = String(value ?? '')
    .toUpperCase()
    .replace(/^HMAC/, '')
    .replace(/[^A-Z0-9]/g, '');
  switch (clean) {
    case '':
    case 'SHA1':
      return 'SHA-1';
    case 'SHA256':
      return 'SHA-256';
    case 'SHA512':
      return 'SHA-512';
    default:
      return null;
  }
}

export function parseDigits(value: unknown): Digits | null {
  const n = Number(value ?? DEFAULT_DIGITS);
  return n === 6 || n === 7 || n === 8 ? n : null;
}

export function parsePeriod(value: unknown): number | null {
  if (value === undefined || value === null || value === '') {
    return DEFAULT_PERIOD;
  }
  const n = Number(value);
  return Number.isInteger(n) && n >= 1 && n <= 86_400 ? n : null;
}

/** Encodes a non-negative integer counter as an 8-byte big-endian buffer. */
function counterToBytes(counter: number): Uint8Array<ArrayBuffer> {
  if (!Number.isSafeInteger(counter) || counter < 0) {
    throw new Error('Counter must be a non-negative safe integer.');
  }
  const buf = new Uint8Array(8);
  const view = new DataView(buf.buffer);
  view.setUint32(0, Math.floor(counter / 0x1_0000_0000));
  view.setUint32(4, counter >>> 0);
  return buf;
}

async function importHmacKey(secret: Uint8Array<ArrayBuffer>, algorithm: HashAlgorithm): Promise<CryptoKey> {
  if (secret.length === 0) {
    throw new Error('Secret must not be empty.');
  }
  return crypto.subtle.importKey('raw', secret, { name: 'HMAC', hash: algorithm }, false, ['sign']);
}

/** RFC 4226 section 5.3 dynamic truncation followed by modulo reduction. */
function truncate(hmac: Uint8Array, digits: Digits): string {
  const offset = (hmac[hmac.length - 1] as number) & 0x0f;
  const binary =
    (((hmac[offset] as number) & 0x7f) << 24) |
    (((hmac[offset + 1] as number) & 0xff) << 16) |
    (((hmac[offset + 2] as number) & 0xff) << 8) |
    ((hmac[offset + 3] as number) & 0xff);
  return (binary % 10 ** digits).toString().padStart(digits, '0');
}

export interface OtpParams {
  /** Raw secret bytes or a Base32 string. */
  secret: Uint8Array<ArrayBuffer> | string;
  algorithm?: HashAlgorithm;
  digits?: Digits;
}

function secretBytes(secret: Uint8Array<ArrayBuffer> | string): Uint8Array<ArrayBuffer> {
  return typeof secret === 'string' ? base32Decode(secret) : secret;
}

/** RFC 4226 HOTP value for the given counter. */
export async function generateHotp(params: OtpParams, counter: number): Promise<string> {
  const algorithm = params.algorithm ?? DEFAULT_ALGORITHM;
  const digits = params.digits ?? DEFAULT_DIGITS;
  const key = await importHmacKey(secretBytes(params.secret), algorithm);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', key, counterToBytes(counter)));
  return truncate(mac, digits);
}

/** The RFC 6238 time step counter T for a timestamp in milliseconds. */
export function timeStep(period: number, nowMs: number = Date.now(), t0Seconds = 0): number {
  return Math.floor((Math.floor(nowMs / 1000) - t0Seconds) / period);
}

/** RFC 6238 TOTP value at the given time. */
export async function generateTotp(
  params: OtpParams & { period?: number },
  nowMs: number = Date.now(),
): Promise<string> {
  const period = params.period ?? DEFAULT_PERIOD;
  return generateHotp(params, timeStep(period, nowMs));
}

/** Seconds (fractional) left before the current TOTP code rolls over. */
export function secondsRemaining(period: number, nowMs: number = Date.now()): number {
  const periodMs = period * 1000;
  return (periodMs - (nowMs % periodMs)) / 1000;
}

/**
 * Generates the current code for an account. For HOTP this returns the code
 * for the stored counter and does not advance it. Callers that consume an
 * HOTP code must persist counter + 1 themselves.
 */
export async function generateCode(account: AccountEntry, nowMs: number = Date.now()): Promise<string> {
  const params: OtpParams = { secret: account.secret, algorithm: account.algorithm, digits: account.digits };
  if (account.type === 'hotp') {
    return generateHotp(params, account.counter);
  }
  return generateTotp({ ...params, period: account.period }, nowMs);
}

/** Splits a code into readable groups, e.g. "123 456" or "1234 5678". */
export function formatCode(code: string): string {
  if (code.length === 6) {
    return `${code.slice(0, 3)} ${code.slice(3)}`;
  }
  if (code.length === 8) {
    return `${code.slice(0, 4)} ${code.slice(4)}`;
  }
  return code;
}
