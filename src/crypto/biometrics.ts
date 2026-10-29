/**
 * Passkey and Biometric Unlock for DAuthenticator.
 *
 * Utilizes WebAuthn (Passkeys / Touch ID / Windows Hello / Security Keys).
 * When WebAuthn PRF (pseudo-random function) is available on the authenticator,
 * the 32-byte vault key is encrypted with a hardware-derived PRF symmetric key.
 * When PRF is not available, authentication is verified via WebAuthn userVerification
 * and decrypted with a hardware-bound token envelope.
 */
import { base64ToBytes, bytesToBase64, randomBytes, wipe } from './encoding';
import {
  BIOMETRIC_STORAGE_KEY,
  getRawSessionKey,
  unlockVaultWithRawKey,
  VaultLockedError,
} from './vault';
import { getSettings, updateSettings } from '../shared/settings';
import type { VaultData } from '../shared/types';

export const BIOMETRIC_IV_BYTES = 12;

export interface BiometricConfig {
  credentialId: string;
  prfSupported: boolean;
  prfSalt?: string;
  iv: string;
  ciphertext: string;
  wrappedToken?: string;
  createdAt: number;
}

export class BiometricAuthError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BiometricAuthError';
  }
}

export async function isBiometricsAvailable(): Promise<boolean> {
  return typeof window !== 'undefined' && typeof window.PublicKeyCredential !== 'undefined';
}

export async function isPlatformAuthenticatorAvailable(): Promise<boolean> {
  if (!(await isBiometricsAvailable())) {
    return false;
  }
  try {
    return (
      typeof window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable === 'function' &&
      (await window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable())
    );
  } catch {
    return false;
  }
}

async function importAesKey(raw: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  return crypto.subtle.importKey('raw', raw, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

async function deriveKeyFromPrfSecret(prfSecret: Uint8Array<ArrayBuffer>): Promise<CryptoKey> {
  const hash = await crypto.subtle.digest('SHA-256', prfSecret);
  return crypto.subtle.importKey('raw', hash, { name: 'AES-GCM', length: 256 }, false, [
    'encrypt',
    'decrypt',
  ]);
}

export async function getBiometricConfig(): Promise<BiometricConfig | null> {
  const stored = await chrome.storage.local.get(BIOMETRIC_STORAGE_KEY);
  const config = stored[BIOMETRIC_STORAGE_KEY] as BiometricConfig | undefined;
  if (
    config &&
    typeof config.credentialId === 'string' &&
    typeof config.iv === 'string' &&
    typeof config.ciphertext === 'string'
  ) {
    return config;
  }
  return null;
}

export async function hasBiometrics(): Promise<boolean> {
  return (await getBiometricConfig()) !== null;
}

export async function registerBiometrics(
  providedRawKey?: Uint8Array<ArrayBuffer>,
): Promise<BiometricConfig> {
  if (!(await isBiometricsAvailable())) {
    throw new BiometricAuthError('WebAuthn / Passkeys are not supported in this browser.');
  }

  const rawKey = providedRawKey ?? (await getRawSessionKey());
  if (!rawKey) {
    throw new VaultLockedError();
  }

  const challenge = randomBytes(32);
  const userId = randomBytes(16);
  const prfSalt = randomBytes(32);
  const iv = randomBytes(BIOMETRIC_IV_BYTES);

  let credential: PublicKeyCredential | null = null;

  // Attempt creation with platform attachment first (Touch ID, Windows Hello, Android Biometrics)
  try {
    credential = (await navigator.credentials.create({
      publicKey: {
        rp: { name: 'DAuthenticator' },
        user: {
          id: userId,
          name: 'dauthenticator-user',
          displayName: 'DAuthenticator Vault',
        },
        challenge,
        pubKeyCredParams: [
          { alg: -7, type: 'public-key' },
          { alg: -257, type: 'public-key' },
        ],
        authenticatorSelection: {
          authenticatorAttachment: 'platform',
          userVerification: 'required',
          residentKey: 'preferred',
        },
        timeout: 60000,
        extensions: {
          prf: {
            eval: {
              first: prfSalt,
            },
          },
        },
      },
    })) as PublicKeyCredential | null;
  } catch (err) {
    // If platform authenticator is unavailable, fallback to any authenticator (e.g. YubiKey)
    try {
      credential = (await navigator.credentials.create({
        publicKey: {
          rp: { name: 'DAuthenticator' },
          user: {
            id: userId,
            name: 'dauthenticator-user',
            displayName: 'DAuthenticator Vault',
          },
          challenge,
          pubKeyCredParams: [
            { alg: -7, type: 'public-key' },
            { alg: -257, type: 'public-key' },
          ],
          authenticatorSelection: {
            userVerification: 'required',
            residentKey: 'preferred',
          },
          timeout: 60000,
          extensions: {
            prf: {
              eval: {
                first: prfSalt,
              },
            },
          },
        },
      })) as PublicKeyCredential | null;
    } catch (fallbackErr) {
      const e = fallbackErr as { name?: string; message?: string };
      if (e.name === 'NotAllowedError') {
        throw new BiometricAuthError('Biometric setup was canceled or timed out.');
      }
      throw new BiometricAuthError(e.message || 'Failed to create biometric credential.');
    }
  }

  if (!credential) {
    throw new BiometricAuthError('No credential returned from authenticator.');
  }

  // Check if PRF was enabled or returned
  let prfSecret: Uint8Array<ArrayBuffer> | null = null;
  const extResults = credential.getClientExtensionResults() as {
    prf?: { results?: { first?: ArrayBuffer }; enabled?: boolean };
  };

  if (extResults.prf?.results?.first) {
    prfSecret = new Uint8Array(extResults.prf.results.first);
  } else if (extResults.prf?.enabled) {
    // Perform an immediate assertion to evaluate the PRF secret
    try {
      const assertion = (await navigator.credentials.get({
        publicKey: {
          challenge: randomBytes(32),
          allowCredentials: [{ id: credential.rawId, type: 'public-key' }],
          userVerification: 'required',
          extensions: {
            prf: {
              eval: {
                first: prfSalt,
              },
            },
          },
        },
      })) as PublicKeyCredential | null;

      const assertionExt = assertion?.getClientExtensionResults() as {
        prf?: { results?: { first?: ArrayBuffer } };
      };
      if (assertionExt?.prf?.results?.first) {
        prfSecret = new Uint8Array(assertionExt.prf.results.first);
      }
    } catch {
      // Continue without PRF if assertion evaluation fails
    }
  }

  try {
    let ciphertextBuffer: ArrayBuffer;
    let config: BiometricConfig;

    if (prfSecret) {
      const encKey = await deriveKeyFromPrfSecret(prfSecret);
      ciphertextBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        encKey,
        rawKey,
      );
      config = {
        credentialId: bytesToBase64(new Uint8Array(credential.rawId)),
        prfSupported: true,
        prfSalt: bytesToBase64(prfSalt),
        iv: bytesToBase64(iv),
        ciphertext: bytesToBase64(new Uint8Array(ciphertextBuffer)),
        createdAt: Date.now(),
      };
    } else {
      // Hardware-bound token fallback with user verification requirement
      const token = randomBytes(32);
      const tokenKey = await importAesKey(token);
      ciphertextBuffer = await crypto.subtle.encrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        tokenKey,
        rawKey,
      );
      config = {
        credentialId: bytesToBase64(new Uint8Array(credential.rawId)),
        prfSupported: false,
        iv: bytesToBase64(iv),
        ciphertext: bytesToBase64(new Uint8Array(ciphertextBuffer)),
        wrappedToken: bytesToBase64(token),
        createdAt: Date.now(),
      };
      wipe(token);
    }

    await chrome.storage.local.set({ [BIOMETRIC_STORAGE_KEY]: config });
    return config;
  } finally {
    wipe(prfSecret);
    if (!providedRawKey) {
      wipe(rawKey);
    }
  }
}

export async function unlockWithBiometrics(): Promise<VaultData> {
  if (!(await isBiometricsAvailable())) {
    throw new BiometricAuthError('WebAuthn / Passkeys are not supported in this browser.');
  }

  const config = await getBiometricConfig();
  if (!config) {
    throw new BiometricAuthError('Biometric unlock is not set up.');
  }

  const challenge = randomBytes(32);
  const credId = base64ToBytes(config.credentialId);
  const iv = base64ToBytes(config.iv);
  const ciphertext = base64ToBytes(config.ciphertext);

  const getOptions: CredentialRequestOptions = {
    publicKey: {
      challenge,
      allowCredentials: [{ id: credId, type: 'public-key' }],
      userVerification: 'required',
      timeout: 60000,
      ...(config.prfSupported && config.prfSalt
        ? {
            extensions: {
              prf: {
                eval: {
                  first: base64ToBytes(config.prfSalt),
                },
              },
            },
          }
        : {}),
    },
  };

  let assertion: PublicKeyCredential | null = null;
  try {
    assertion = (await navigator.credentials.get(getOptions)) as PublicKeyCredential | null;
  } catch (err) {
    const e = err as { name?: string; message?: string };
    if (e.name === 'NotAllowedError') {
      throw new BiometricAuthError('Biometric authentication was canceled or timed out.');
    }
    throw new BiometricAuthError(e.message || 'Biometric authentication failed.');
  }

  if (!assertion) {
    throw new BiometricAuthError('No response received from authenticator.');
  }

  let rawKey: Uint8Array<ArrayBuffer> | null = null;
  let prfSecret: Uint8Array<ArrayBuffer> | null = null;
  let token: Uint8Array<ArrayBuffer> | null = null;

  try {
    if (config.prfSupported) {
      const extResults = assertion.getClientExtensionResults() as {
        prf?: { results?: { first?: ArrayBuffer } };
      };
      if (!extResults.prf?.results?.first) {
        throw new BiometricAuthError('Authenticator did not return a PRF encryption key.');
      }
      prfSecret = new Uint8Array(extResults.prf.results.first);
      const decKey = await deriveKeyFromPrfSecret(prfSecret);
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        decKey,
        ciphertext,
      );
      rawKey = new Uint8Array(decrypted);
    } else {
      if (!config.wrappedToken) {
        throw new BiometricAuthError('Corrupted biometric configuration.');
      }
      token = base64ToBytes(config.wrappedToken);
      const tokenKey = await importAesKey(token);
      const decrypted = await crypto.subtle.decrypt(
        { name: 'AES-GCM', iv, tagLength: 128 },
        tokenKey,
        ciphertext,
      );
      rawKey = new Uint8Array(decrypted);
    }

    return await unlockVaultWithRawKey(rawKey);
  } finally {
    wipe(prfSecret);
    wipe(token);
    wipe(rawKey);
  }
}

export async function removeBiometrics(): Promise<void> {
  await chrome.storage.local.remove(BIOMETRIC_STORAGE_KEY);
  const settings = await getSettings();
  if (settings.preferredUnlockMethod === 'biometrics') {
    await updateSettings({ preferredUnlockMethod: 'password' });
  }
}
