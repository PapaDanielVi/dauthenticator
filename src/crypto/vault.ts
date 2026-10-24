/**
 * Zero-knowledge vault.
 *
 * The plaintext account list only exists in memory. At rest it is serialized,
 * encrypted with AES-256-GCM under a key derived from the master password with
 * PBKDF2-SHA-256 (600,000 iterations, 16 byte random salt) and written to
 * chrome.storage.local as { version, salt, iv, ciphertext }.
 *
 * While unlocked, the derived key is cached in chrome.storage.session, which
 * Chrome keeps in memory only and clears when the browser exits. A CryptoKey
 * object cannot be structured-cloned into extension storage, so the 32 raw key
 * bytes are cached instead and re-imported as a non-extractable AES-GCM key
 * whenever a context needs it. The master password itself is never stored.
 */
import type { AccountEntry, VaultData } from '../shared/types';
import { base64ToBytes, bytesToBase64, randomBytes, utf8Decode, utf8Encode, wipe } from './encoding';
import { sanitizeAccount } from '../shared/accounts';

export const VAULT_STORAGE_KEY = 'dauth.vault';
export const SESSION_STORAGE_KEY = 'dauth.session';

/** Current on-disk format. The version pins the KDF parameters below. */
export const VAULT_FORMAT_VERSION = 1;
export const PBKDF2_ITERATIONS = 600_000;
export const SALT_BYTES = 16;
export const IV_BYTES = 12;
export const KEY_BITS = 256;
export const MIN_PASSWORD_LENGTH = 8;

interface KdfParams {
  iterations: number;
  hash: 'SHA-256';
}

const KDF_BY_VERSION: Readonly<Record<number, KdfParams>> = {
  1: { iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
};

/** The only shape that is ever persisted for vault contents. */
export interface EncryptedVault {
  version: number;
  salt: string;
  iv: string;
  ciphertext: string;
}

interface SessionState {
  /** Base64 of the 32 byte AES key derived from the master password. */
  key: string;
  /** Salt of the vault this key belongs to, used to detect stale sessions. */
  salt: string;
  unlockedAt: number;
}

export class VaultLockedError extends Error {
  constructor() {
    super('The vault is locked.');
    this.name = 'VaultLockedError';
  }
}

export class VaultMissingError extends Error {
  constructor() {
    super('No vault has been created yet.');
    this.name = 'VaultMissingError';
  }
}

export class WrongPasswordError extends Error {
  constructor(message = 'Wrong password, or the data has been tampered with.') {
    super(message);
    this.name = 'WrongPasswordError';
  }
}

function kdfFor(version: number): KdfParams {
  const params = KDF_BY_VERSION[version];
  if (!params) {
    throw new Error(`Unsupported vault version ${version}.`);
  }
  return params;
}

/** Binds the format version into the GCM tag so it cannot be swapped silently. */
function additionalData(version: number): Uint8Array<ArrayBuffer> {
  return utf8Encode(`DAuthenticator:vault:v${version}`);
}

export function isEncryptedVault(value: unknown): value is EncryptedVault {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const v = value as Record<string, unknown>;
  return (
    typeof v.version === 'number' &&
    typeof v.salt === 'string' &&
    typeof v.iv === 'string' &&
    typeof v.ciphertext === 'string'
  );
}

/** Derives the raw 256-bit AES key with PBKDF2. Caller owns (and should wipe) the result. */
export async function deriveKeyBytes(
  password: string,
  salt: Uint8Array<ArrayBuffer>,
  version: number = VAULT_FORMAT_VERSION,
): Promise<Uint8Array<ArrayBuffer>> {
  const { iterations, hash } = kdfFor(version);
  const passwordBytes = utf8Encode(password.normalize('NFKC'));
  try {
    const baseKey = await crypto.subtle.importKey('raw', passwordBytes, 'PBKDF2', false, ['deriveBits']);
    const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations, hash }, baseKey, KEY_BITS);
    return new Uint8Array(bits);
  } finally {
    wipe(passwordBytes);
  }
}

async function importAesKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: KEY_BITS }, false, ['encrypt', 'decrypt']);
}

/** Encrypts any JSON value under an existing key. A fresh IV is drawn for every call. */
export async function encryptJson(
  value: unknown,
  key: CryptoKey,
  salt: string,
  version: number = VAULT_FORMAT_VERSION,
): Promise<EncryptedVault> {
  const iv = randomBytes(IV_BYTES);
  const plaintext = utf8Encode(JSON.stringify(value));
  try {
    const ciphertext = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv, additionalData: additionalData(version), tagLength: 128 },
      key,
      plaintext,
    );
    return { version, salt, iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext)) };
  } finally {
    wipe(plaintext);
  }
}

export async function decryptJson<T>(envelope: EncryptedVault, key: CryptoKey): Promise<T> {
  let plaintext: Uint8Array | null = null;
  try {
    const buffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv: base64ToBytes(envelope.iv),
        additionalData: additionalData(envelope.version),
        tagLength: 128,
      },
      key,
      base64ToBytes(envelope.ciphertext),
    );
    plaintext = new Uint8Array(buffer);
    return JSON.parse(utf8Decode(plaintext)) as T;
  } catch (error) {
    if ((error as { name?: unknown } | null)?.name === 'OperationError') {
      throw new WrongPasswordError();
    }
    throw error;
  } finally {
    wipe(plaintext);
  }
}

/** Encrypts a value under a brand new salt and password. Used for password changes. */
export async function encryptWithPassword(value: unknown, password: string): Promise<EncryptedVault> {
  const salt = randomBytes(SALT_BYTES);
  const raw = await deriveKeyBytes(password, salt);
  try {
    return await encryptJson(value, await importAesKey(raw), bytesToBase64(salt));
  } finally {
    wipe(raw);
  }
}

/** Decrypts an envelope (vault, sync copy or backup file) with a password. */
export async function decryptWithPassword<T>(envelope: EncryptedVault, password: string): Promise<T> {
  const raw = await deriveKeyBytes(password, base64ToBytes(envelope.salt), envelope.version);
  try {
    return await decryptJson<T>(envelope, await importAesKey(raw));
  } finally {
    wipe(raw);
  }
}

/**
 * Restricts chrome.storage.local and chrome.storage.session to trusted
 * extension contexts (service worker, popup, options page), so content scripts
 * can never read the encrypted vault or the cached session key.
 */
export async function hardenStorageAccess(): Promise<void> {
  await chrome.storage.local.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
  await chrome.storage.session.setAccessLevel({ accessLevel: 'TRUSTED_CONTEXTS' });
}

export async function getEncryptedVault(): Promise<EncryptedVault | null> {
  const stored = await chrome.storage.local.get(VAULT_STORAGE_KEY);
  const value: unknown = stored[VAULT_STORAGE_KEY];
  return isEncryptedVault(value) ? value : null;
}

export async function hasVault(): Promise<boolean> {
  return (await getEncryptedVault()) !== null;
}

async function writeEncryptedVault(envelope: EncryptedVault): Promise<void> {
  await chrome.storage.local.set({ [VAULT_STORAGE_KEY]: envelope });
}

async function cacheSessionKey(raw: Uint8Array, salt: string): Promise<void> {
  const state: SessionState = { key: bytesToBase64(raw), salt, unlockedAt: Date.now() };
  await chrome.storage.session.set({ [SESSION_STORAGE_KEY]: state });
}

async function readSessionState(): Promise<SessionState | null> {
  const stored = await chrome.storage.session.get(SESSION_STORAGE_KEY);
  const value = stored[SESSION_STORAGE_KEY] as SessionState | undefined;
  return value && typeof value.key === 'string' && typeof value.salt === 'string' ? value : null;
}

/** Returns the AES key for the current vault, or throws if the session is locked. */
async function sessionKey(envelope: EncryptedVault): Promise<CryptoKey> {
  const state = await readSessionState();
  if (!state) {
    throw new VaultLockedError();
  }
  if (state.salt !== envelope.salt) {
    // The vault was re-keyed elsewhere (password change or restore). Force a fresh unlock.
    await lockVault();
    throw new VaultLockedError();
  }
  const raw = base64ToBytes(state.key);
  try {
    return await importAesKey(raw);
  } finally {
    wipe(raw);
  }
}

export async function isUnlocked(): Promise<boolean> {
  const [envelope, state] = await Promise.all([getEncryptedVault(), readSessionState()]);
  return envelope !== null && state !== null && state.salt === envelope.salt;
}

export async function getUnlockedAt(): Promise<number | null> {
  return (await readSessionState())?.unlockedAt ?? null;
}

function emptyVault(): VaultData {
  return { version: 1, accounts: [] };
}

function normalizeVault(value: unknown): VaultData {
  if (!value || typeof value !== 'object' || !Array.isArray((value as VaultData).accounts)) {
    throw new Error('Decrypted vault has an unexpected structure.');
  }
  const accounts: AccountEntry[] = [];
  for (const raw of (value as VaultData).accounts) {
    const account = sanitizeAccount(raw);
    if (account) {
      accounts.push(account);
    }
  }
  return { version: 1, accounts };
}

export function assertPasswordStrength(password: string): void {
  if (password.length < MIN_PASSWORD_LENGTH) {
    throw new Error(`The master password must be at least ${MIN_PASSWORD_LENGTH} characters long.`);
  }
}

/** First-run setup: creates an empty vault protected by the given master password. */
export async function createVault(password: string): Promise<void> {
  if (await hasVault()) {
    throw new Error('A vault already exists.');
  }
  assertPasswordStrength(password);
  const salt = randomBytes(SALT_BYTES);
  const saltB64 = bytesToBase64(salt);
  const raw = await deriveKeyBytes(password, salt);
  try {
    const envelope = await encryptJson(emptyVault(), await importAesKey(raw), saltB64);
    await writeEncryptedVault(envelope);
    await cacheSessionKey(raw, saltB64);
  } finally {
    wipe(raw);
  }
}

/** Verifies the master password, caches the session key and returns the vault. */
export async function unlockVault(password: string): Promise<VaultData> {
  const envelope = await getEncryptedVault();
  if (!envelope) {
    throw new VaultMissingError();
  }
  const raw = await deriveKeyBytes(password, base64ToBytes(envelope.salt), envelope.version);
  try {
    const data = normalizeVault(await decryptJson<unknown>(envelope, await importAesKey(raw)));
    await cacheSessionKey(raw, envelope.salt);
    return data;
  } finally {
    wipe(raw);
  }
}

/** Checks a password against the stored vault without touching the session. */
export async function verifyPassword(password: string): Promise<boolean> {
  const envelope = await getEncryptedVault();
  if (!envelope) {
    throw new VaultMissingError();
  }
  try {
    await decryptWithPassword<unknown>(envelope, password);
    return true;
  } catch (error) {
    if (error instanceof WrongPasswordError) {
      return false;
    }
    throw error;
  }
}

export async function lockVault(): Promise<void> {
  await chrome.storage.session.remove(SESSION_STORAGE_KEY);
}

/** Decrypts the vault with the cached session key. Throws VaultLockedError when locked. */
export async function loadVault(): Promise<VaultData> {
  const envelope = await getEncryptedVault();
  if (!envelope) {
    throw new VaultMissingError();
  }
  const key = await sessionKey(envelope);
  return normalizeVault(await decryptJson<unknown>(envelope, key));
}

/** Re-encrypts and persists the vault with a fresh IV, keeping the current salt. */
export async function saveVault(data: VaultData): Promise<void> {
  const envelope = await getEncryptedVault();
  if (!envelope) {
    throw new VaultMissingError();
  }
  const key = await sessionKey(envelope);
  const next = await encryptJson(normalizeVault(data), key, envelope.salt, VAULT_FORMAT_VERSION);
  await writeEncryptedVault(next);
}

let writeQueue: Promise<unknown> = Promise.resolve();

/**
 * Read-modify-write helper. Calls made from the same context are serialized so
 * concurrent edits (for example an HOTP bump and a rename) do not clobber each other.
 */
export function updateVault(mutate: (data: VaultData) => VaultData | void): Promise<VaultData> {
  const run = async (): Promise<VaultData> => {
    const current = await loadVault();
    const next = mutate(current) ?? current;
    await saveVault(next);
    return next;
  };
  const result = writeQueue.then(run, run);
  writeQueue = result.catch(() => undefined);
  return result;
}

/** Re-encrypts the vault under a new password and salt, then refreshes the session. */
export async function changePassword(currentPassword: string, nextPassword: string): Promise<void> {
  assertPasswordStrength(nextPassword);
  const envelope = await getEncryptedVault();
  if (!envelope) {
    throw new VaultMissingError();
  }
  const data = normalizeVault(await decryptWithPassword<unknown>(envelope, currentPassword));
  const salt = randomBytes(SALT_BYTES);
  const saltB64 = bytesToBase64(salt);
  const raw = await deriveKeyBytes(nextPassword, salt);
  try {
    const next = await encryptJson(data, await importAesKey(raw), saltB64);
    await writeEncryptedVault(next);
    await cacheSessionKey(raw, saltB64);
  } finally {
    wipe(raw);
  }
}

/** Decrypts an arbitrary envelope with the current session key, if it shares the vault salt. */
export async function decryptWithSession<T>(envelope: EncryptedVault): Promise<T | null> {
  const current = await getEncryptedVault();
  if (!current || current.salt !== envelope.salt) {
    return null;
  }
  try {
    return await decryptJson<T>(envelope, await sessionKey(current));
  } catch (error) {
    if (error instanceof WrongPasswordError || error instanceof VaultLockedError) {
      return null;
    }
    throw error;
  }
}

/** Permanently removes the local vault and the session key. */
export async function destroyVault(): Promise<void> {
  await Promise.all([chrome.storage.local.remove(VAULT_STORAGE_KEY), lockVault()]);
}
