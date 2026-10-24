/**
 * Small, dependency-free byte encoders used across the vault, the OTP engine
 * and the importers.
 */

const textEncoder = new TextEncoder();
const textDecoder = new TextDecoder();

export function utf8Encode(value: string): Uint8Array<ArrayBuffer> {
  return textEncoder.encode(value);
}

export function utf8Decode(bytes: Uint8Array): string {
  return textDecoder.decode(bytes);
}

/** Encodes bytes as standard (not URL-safe) padded Base64. */
export function bytesToBase64(bytes: Uint8Array): string {
  let binary = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    binary += String.fromCharCode(...bytes.subarray(i, i + chunk));
  }
  return btoa(binary);
}

/**
 * Decodes standard or URL-safe Base64, with or without padding. Whitespace is
 * ignored. Throws on characters outside the Base64 alphabets.
 */
export function base64ToBytes(input: string): Uint8Array<ArrayBuffer> {
  let normalized = input.replace(/\s+/g, '').replace(/-/g, '+').replace(/_/g, '/');
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(normalized)) {
    throw new Error('Invalid Base64 data.');
  }
  normalized = normalized.replace(/=+$/, '');
  const remainder = normalized.length % 4;
  if (remainder === 1) {
    throw new Error('Invalid Base64 length.');
  }
  if (remainder > 0) {
    normalized += '='.repeat(4 - remainder);
  }
  const binary = atob(normalized);
  const out = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    out[i] = binary.charCodeAt(i);
  }
  return out;
}

export function hexToBytes(hex: string): Uint8Array<ArrayBuffer> {
  const clean = hex.replace(/\s+/g, '');
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new Error('Invalid hex string.');
  }
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i += 1) {
    out[i] = Number.parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');
}

export function randomBytes(length: number): Uint8Array<ArrayBuffer> {
  return crypto.getRandomValues(new Uint8Array(length));
}

/** Concatenates byte arrays into a fresh buffer. */
export function concatBytes(...parts: Uint8Array[]): Uint8Array<ArrayBuffer> {
  const total = parts.reduce((sum, p) => sum + p.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const part of parts) {
    out.set(part, offset);
    offset += part.length;
  }
  return out;
}

/** Overwrites a buffer with zeros. Best effort hygiene for key material. */
export function wipe(bytes: Uint8Array | null | undefined): void {
  if (bytes) {
    bytes.fill(0);
  }
}
