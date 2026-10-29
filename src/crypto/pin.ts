/**
 * Quick PIN unlock for DAuthenticator.
 *
 * Encrypts the 32-byte raw vault key with AES-256-GCM under a key derived
 * from the user's numeric PIN using PBKDF2-SHA-256 (300,000 iterations).
 * Includes rate limiting and lockout after repeated failed attempts.
 */
import { base64ToBytes, bytesToBase64, randomBytes, wipe } from './encoding';
import {
  PIN_STORAGE_KEY,
  getRawSessionKey,
  unlockVaultWithRawKey,
  VaultLockedError,
} from './vault';
import { getSettings, updateSettings } from '../shared/settings';
import type { VaultData } from '../shared/types';

export const MIN_PIN_LENGTH = 4;
export const MAX_PIN_LENGTH = 8;
export const PIN_PBKDF2_ITERATIONS = 300_000;
export const PIN_SALT_BYTES = 16;
export const PIN_IV_BYTES = 12;
export const MAX_PIN_FAILED_ATTEMPTS = 5;
export const PIN_LOCKOUT_MS = 5 * 60 * 1000; // 5 minutes

export interface PinConfig {
  salt: string;
  iv: string;
  ciphertext: string;
  iterations: number;
  failedAttempts: number;
  lockedUntil: number;
  createdAt: number;
}

export class PinLockoutError extends Error {
  constructor(public readonly remainingSeconds: number) {
    super(
      `PIN unlock is temporarily locked. Try again in ${remainingSeconds} second${
        remainingSeconds === 1 ? '' : 's'
      }, or unlock with your master password.`,
    );
    this.name = 'PinLockoutError';
  }
}

export class WrongPinError extends Error {
  constructor(public readonly remainingAttempts: number) {
    const message =
      remainingAttempts > 0
        ? `Incorrect PIN. ${remainingAttempts} attempt${
            remainingAttempts === 1 ? '' : 's'
          } remaining before temporary lockout.`
        : 'Incorrect PIN. PIN unlock is now locked. Unlock with your master password.';
    super(message);
    this.name = 'WrongPinError';
  }
}

export function assertPinFormat(pin: string): void {
  if (!/^\d{4,8}$/.test(pin)) {
    throw new Error(`PIN must be between ${MIN_PIN_LENGTH} and ${MAX_PIN_LENGTH} digits.`);
  }
}

async function derivePinKey(
  pin: string,
  salt: Uint8Array<ArrayBuffer>,
  iterations: number = PIN_PBKDF2_ITERATIONS,
): Promise<CryptoKey> {
  const encoder = new TextEncoder();
  const pinBytes = encoder.encode(pin);
  try {
    const baseKey = await crypto.subtle.importKey('raw', pinBytes, 'PBKDF2', false, ['deriveKey']);
    return await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt, iterations, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt'],
    );
  } finally {
    wipe(pinBytes);
  }
}

export async function getPinConfig(): Promise<PinConfig | null> {
  const stored = await chrome.storage.local.get(PIN_STORAGE_KEY);
  const config = stored[PIN_STORAGE_KEY] as PinConfig | undefined;
  if (
    config &&
    typeof config.salt === 'string' &&
    typeof config.iv === 'string' &&
    typeof config.ciphertext === 'string'
  ) {
    return config;
  }
  return null;
}

export async function hasPin(): Promise<boolean> {
  return (await getPinConfig()) !== null;
}

export async function setupPin(pin: string, providedRawKey?: Uint8Array<ArrayBuffer>): Promise<void> {
  assertPinFormat(pin);
  const rawKey = providedRawKey ?? (await getRawSessionKey());
  if (!rawKey) {
    throw new VaultLockedError();
  }

  const salt = randomBytes(PIN_SALT_BYTES);
  const iv = randomBytes(PIN_IV_BYTES);
  const pinKey = await derivePinKey(pin, salt, PIN_PBKDF2_ITERATIONS);

  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      pinKey,
      rawKey,
    );

    const config: PinConfig = {
      salt: bytesToBase64(salt),
      iv: bytesToBase64(iv),
      ciphertext: bytesToBase64(new Uint8Array(ciphertext)),
      iterations: PIN_PBKDF2_ITERATIONS,
      failedAttempts: 0,
      lockedUntil: 0,
      createdAt: Date.now(),
    };

    await chrome.storage.local.set({ [PIN_STORAGE_KEY]: config });
  } finally {
    if (!providedRawKey) {
      wipe(rawKey);
    }
  }
}

export async function unlockWithPin(pin: string): Promise<VaultData> {
  assertPinFormat(pin);
  const config = await getPinConfig();
  if (!config) {
    throw new Error('Quick PIN unlock is not configured.');
  }

  const now = Date.now();
  if (config.lockedUntil > now) {
    const remainingSeconds = Math.ceil((config.lockedUntil - now) / 1000);
    throw new PinLockoutError(remainingSeconds);
  }

  const salt = base64ToBytes(config.salt);
  const iv = base64ToBytes(config.iv);
  const ciphertext = base64ToBytes(config.ciphertext);
  const pinKey = await derivePinKey(pin, salt, config.iterations);

  let rawKey: Uint8Array<ArrayBuffer> | null = null;
  try {
    const decryptedBuffer = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, tagLength: 128 },
      pinKey,
      ciphertext,
    );
    rawKey = new Uint8Array(decryptedBuffer);

    // Reset failed counter on success
    config.failedAttempts = 0;
    config.lockedUntil = 0;
    await chrome.storage.local.set({ [PIN_STORAGE_KEY]: config });

    return await unlockVaultWithRawKey(rawKey);
  } catch (error) {
    if (error instanceof PinLockoutError) {
      throw error;
    }

    // Decryption failed -> wrong PIN
    config.failedAttempts = (config.failedAttempts || 0) + 1;
    if (config.failedAttempts >= MAX_PIN_FAILED_ATTEMPTS) {
      config.lockedUntil = now + PIN_LOCKOUT_MS;
    }
    await chrome.storage.local.set({ [PIN_STORAGE_KEY]: config });

    const remaining = Math.max(0, MAX_PIN_FAILED_ATTEMPTS - config.failedAttempts);
    throw new WrongPinError(remaining);
  } finally {
    wipe(rawKey);
  }
}

export async function removePin(): Promise<void> {
  await chrome.storage.local.remove(PIN_STORAGE_KEY);
  const settings = await getSettings();
  if (settings.preferredUnlockMethod === 'pin') {
    await updateSettings({ preferredUnlockMethod: 'password' });
  }
}

export async function resetPinLockout(): Promise<void> {
  const config = await getPinConfig();
  if (config && (config.failedAttempts > 0 || config.lockedUntil > 0)) {
    config.failedAttempts = 0;
    config.lockedUntil = 0;
    await chrome.storage.local.set({ [PIN_STORAGE_KEY]: config });
  }
}
