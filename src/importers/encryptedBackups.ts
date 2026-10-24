/**
 * Decryption of password protected backups from other authenticators.
 *
 * Aegis: each password slot stores the vault master key wrapped with AES-256-GCM
 * under scrypt(password, salt, N, r, p). The unwrapped master key then decrypts
 * the Base64 "db" blob, again with AES-256-GCM.
 *
 * 2FAS: "servicesEncrypted" is "ciphertext:salt:iv" (Base64 each), where the key
 * is PBKDF2-SHA-256(password, salt, 10,000 iterations) and the cipher is
 * AES-256-GCM with the tag appended to the ciphertext.
 */
import { scryptAsync } from '@noble/hashes/scrypt.js';
import { base64ToBytes, concatBytes, hexToBytes, utf8Decode, utf8Encode, wipe } from '../crypto/encoding';
import { PasswordRequiredError } from '../shared/errors';

const AES_KEY_BYTES = 32;
const TWOFAS_PBKDF2_ITERATIONS = 10_000;
const AEGIS_PASSWORD_SLOT = 1;
/** Upper bound for scrypt cost parameters from untrusted files (N * r * 128 bytes of RAM). */
const MAX_SCRYPT_MEMORY = 512 * 1024 * 1024;

interface AegisSlot {
  type: number;
  key: string;
  key_params: { nonce: string; tag: string };
  n: number;
  r: number;
  p: number;
  salt: string;
}

export interface AegisFile {
  version: number;
  header: {
    slots: AegisSlot[] | null;
    params: { nonce: string; tag: string } | null;
  };
  db: unknown;
}

async function aesGcmDecrypt(
  keyBytes: Uint8Array<ArrayBuffer>,
  nonce: Uint8Array<ArrayBuffer>,
  ciphertextWithTag: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array<ArrayBuffer>> {
  const key = await crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['decrypt']);
  const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce, tagLength: 128 }, key, ciphertextWithTag);
  return new Uint8Array(plain);
}

export function isAegisFile(value: unknown): value is AegisFile {
  if (!value || typeof value !== 'object') {
    return false;
  }
  const v = value as Partial<AegisFile>;
  return typeof v.version === 'number' && !!v.header && typeof v.header === 'object' && 'db' in v;
}

export function isAegisEncrypted(file: AegisFile): boolean {
  return typeof file.db === 'string';
}

/** Returns the decrypted Aegis database object ({ version, entries, ... }). */
export async function decryptAegis(file: AegisFile, password: string | undefined): Promise<unknown> {
  if (!isAegisEncrypted(file)) {
    return file.db;
  }
  const params = file.header.params;
  const slots = (file.header.slots ?? []).filter((s) => s.type === AEGIS_PASSWORD_SLOT);
  if (!params || slots.length === 0) {
    throw new Error('This Aegis backup has no password slot. Export it again with a password.');
  }
  if (!password) {
    throw new PasswordRequiredError('aegis');
  }

  const passwordBytes = utf8Encode(password);
  let masterKey: Uint8Array<ArrayBuffer> | null = null;
  try {
    for (const slot of slots) {
      if (slot.n * slot.r * 128 > MAX_SCRYPT_MEMORY || slot.p > 16) {
        throw new Error('The Aegis backup uses unreasonable scrypt parameters.');
      }
      const derived = new Uint8Array(
        await scryptAsync(passwordBytes, hexToBytes(slot.salt), { N: slot.n, r: slot.r, p: slot.p, dkLen: AES_KEY_BYTES }),
      );
      try {
        masterKey = await aesGcmDecrypt(
          derived,
          hexToBytes(slot.key_params.nonce),
          concatBytes(hexToBytes(slot.key), hexToBytes(slot.key_params.tag)),
        );
        break;
      } catch {
        // Wrong password for this slot, try the next one.
      } finally {
        wipe(derived);
      }
    }
    if (!masterKey) {
      throw new PasswordRequiredError('aegis', true);
    }
    const plain = await aesGcmDecrypt(
      masterKey,
      hexToBytes(params.nonce),
      concatBytes(base64ToBytes(file.db as string), hexToBytes(params.tag)),
    );
    return JSON.parse(utf8Decode(plain));
  } finally {
    wipe(passwordBytes);
    wipe(masterKey);
  }
}

/** Decrypts a 2FAS "servicesEncrypted" string into the services array. */
export async function decrypt2fasServices(servicesEncrypted: string, password: string | undefined): Promise<unknown[]> {
  if (!password) {
    throw new PasswordRequiredError('2fas');
  }
  const [cipherB64, saltB64, ivB64] = servicesEncrypted.split(':');
  if (!cipherB64 || !saltB64 || !ivB64) {
    throw new Error('The encrypted 2FAS backup is malformed.');
  }
  const passwordKey = await crypto.subtle.importKey('raw', utf8Encode(password), 'PBKDF2', false, ['deriveKey']);
  const key = await crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: base64ToBytes(saltB64), iterations: TWOFAS_PBKDF2_ITERATIONS, hash: 'SHA-256' },
    passwordKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['decrypt'],
  );
  let plain: ArrayBuffer;
  try {
    plain = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: base64ToBytes(ivB64), tagLength: 128 },
      key,
      base64ToBytes(cipherB64),
    );
  } catch {
    throw new PasswordRequiredError('2fas', true);
  }
  const parsed: unknown = JSON.parse(utf8Decode(new Uint8Array(plain)));
  if (!Array.isArray(parsed)) {
    throw new Error('The decrypted 2FAS backup has an unexpected structure.');
  }
  return parsed;
}
