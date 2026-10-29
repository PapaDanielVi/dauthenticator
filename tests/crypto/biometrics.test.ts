import { beforeEach, afterEach, describe, expect, it } from 'vitest';
import { createVault, isUnlocked, lockVault, loadVault } from '../../src/crypto/vault';
import {
  registerBiometrics,
  unlockWithBiometrics,
  hasBiometrics,
  getBiometricConfig,
  removeBiometrics,
  BiometricAuthError,
  isBiometricsAvailable,
} from '../../src/crypto/biometrics';
import { mockLocal, mockSession } from '../setup/chromeMock';

function setMockNavigator(nav: unknown): void {
  Object.defineProperty(globalThis, 'navigator', {
    value: nav,
    configurable: true,
    writable: true,
  });
}

function setMockWindow(win: unknown): void {
  Object.defineProperty(globalThis, 'window', {
    value: win,
    configurable: true,
    writable: true,
  });
}

describe('Biometric & Passkey Unlock', () => {
  const originalWindow = globalThis.window;
  const originalNavigator = globalThis.navigator;

  beforeEach(async () => {
    await mockLocal.clear();
    await mockSession.clear();
  });

  afterEach(() => {
    setMockWindow(originalWindow);
    setMockNavigator(originalNavigator);
  });

  it('detects availability when WebAuthn is present or absent', async () => {
    setMockWindow({});
    expect(await isBiometricsAvailable()).toBe(false);

    setMockWindow({
      PublicKeyCredential: class MockPublicKeyCredential {
        static async isUserVerifyingPlatformAuthenticatorAvailable() {
          return true;
        }
      },
    });

    expect(await isBiometricsAvailable()).toBe(true);
  });

  it('registers passkey with PRF and unlocks vault', async () => {
    await createVault('master-pass-xyz');

    const fakeRawId = new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8]);
    const fakePrfSecret = new Uint8Array(32).fill(42);

    setMockWindow({
      PublicKeyCredential: class MockPublicKeyCredential {},
    });

    setMockNavigator({
      credentials: {
        create: async () => ({
          rawId: fakeRawId.slice().buffer,
          getClientExtensionResults: () => ({
            prf: {
              results: {
                first: fakePrfSecret.slice().buffer,
              },
            },
          }),
        }),
        get: async () => ({
          rawId: fakeRawId.slice().buffer,
          getClientExtensionResults: () => ({
            prf: {
              results: {
                first: fakePrfSecret.slice().buffer,
              },
            },
          }),
        }),
      },
    });

    expect(await hasBiometrics()).toBe(false);
    const config = await registerBiometrics();
    expect(config.prfSupported).toBe(true);
    expect(await hasBiometrics()).toBe(true);
    expect(await getBiometricConfig()).not.toBeNull();

    // Lock vault
    await lockVault();
    expect(await isUnlocked()).toBe(false);

    // Unlock with Biometrics
    const vault = await unlockWithBiometrics();
    expect(vault.version).toBe(1);
    expect(await isUnlocked()).toBe(true);
    expect(await loadVault()).toBeDefined();
  });

  it('registers passkey with non-PRF fallback and unlocks vault', async () => {
    await createVault('master-pass-xyz');

    const fakeRawId = new Uint8Array([10, 20, 30, 40]);

    setMockWindow({
      PublicKeyCredential: class MockPublicKeyCredential {},
    });

    setMockNavigator({
      credentials: {
        create: async () => ({
          rawId: fakeRawId.buffer,
          getClientExtensionResults: () => ({}),
        }),
        get: async () => ({
          rawId: fakeRawId.buffer,
          getClientExtensionResults: () => ({}),
        }),
      },
    });

    const config = await registerBiometrics();
    expect(config.prfSupported).toBe(false);
    expect(typeof config.wrappedToken).toBe('string');

    await lockVault();
    expect(await isUnlocked()).toBe(false);

    const vault = await unlockWithBiometrics();
    expect(vault.version).toBe(1);
    expect(await isUnlocked()).toBe(true);
  });

  it('handles user cancellation cleanly', async () => {
    await createVault('master-pass-xyz');

    setMockWindow({
      PublicKeyCredential: class MockPublicKeyCredential {},
    });

    setMockNavigator({
      credentials: {
        create: async () => {
          const err = new Error('The operation either timed out or was not allowed.');
          err.name = 'NotAllowedError';
          throw err;
        },
      },
    });

    await expect(registerBiometrics()).rejects.toThrow(BiometricAuthError);
  });

  it('removes biometric credentials and resets preferences', async () => {
    await createVault('master-pass-xyz');

    const fakeRawId = new Uint8Array([1, 2, 3]);
    setMockWindow({
      PublicKeyCredential: class MockPublicKeyCredential {},
    });
    setMockNavigator({
      credentials: {
        create: async () => ({
          rawId: fakeRawId.buffer,
          getClientExtensionResults: () => ({}),
        }),
      },
    });

    await registerBiometrics();
    expect(await hasBiometrics()).toBe(true);

    await removeBiometrics();
    expect(await hasBiometrics()).toBe(false);
  });
});
