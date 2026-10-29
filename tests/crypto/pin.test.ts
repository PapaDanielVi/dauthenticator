import { beforeEach, describe, expect, it } from 'vitest';
import { createVault, isUnlocked, lockVault, loadVault } from '../../src/crypto/vault';
import {
  setupPin,
  unlockWithPin,
  hasPin,
  getPinConfig,
  removePin,
  resetPinLockout,
  WrongPinError,
  PinLockoutError,
  MAX_PIN_FAILED_ATTEMPTS,
} from '../../src/crypto/pin';
import { mockLocal, mockSession } from '../setup/chromeMock';

describe('Quick PIN Unlock', () => {
  beforeEach(async () => {
    await mockLocal.clear();
    await mockSession.clear();
  });

  it('rejects invalid PIN formats', async () => {
    await createVault('master-password-123');
    await expect(setupPin('12')).rejects.toThrow();
    await expect(setupPin('abcdef')).rejects.toThrow();
    await expect(setupPin('123456789')).rejects.toThrow();
  });

  it('sets up PIN and unlocks vault without master password', async () => {
    await createVault('master-password-123');
    expect(await hasPin()).toBe(false);

    await setupPin('1234');
    expect(await hasPin()).toBe(true);

    const config = await getPinConfig();
    expect(config?.iterations).toBeGreaterThan(0);
    expect(config?.failedAttempts).toBe(0);

    // Lock vault
    await lockVault();
    expect(await isUnlocked()).toBe(false);

    // Unlock with PIN
    const data = await unlockWithPin('1234');
    expect(data.version).toBe(1);
    expect(await isUnlocked()).toBe(true);
    expect(await loadVault()).toBeDefined();
  });

  it('tracks failed attempts and enforces lockout after max attempts', async () => {
    await createVault('master-password-123');
    await setupPin('5678');
    await lockVault();

    // 4 failed attempts
    for (let i = 1; i < MAX_PIN_FAILED_ATTEMPTS; i++) {
      await expect(unlockWithPin('9999')).rejects.toThrow(WrongPinError);
      const conf = await getPinConfig();
      expect(conf?.failedAttempts).toBe(i);
      expect(await isUnlocked()).toBe(false);
    }

    // 5th attempt triggers lockout
    await expect(unlockWithPin('9999')).rejects.toThrow();
    const confLocked = await getPinConfig();
    expect(confLocked?.failedAttempts).toBe(MAX_PIN_FAILED_ATTEMPTS);
    expect(confLocked?.lockedUntil).toBeGreaterThan(Date.now());

    // Subsequent attempt is blocked by lockout
    await expect(unlockWithPin('5678')).rejects.toThrow(PinLockoutError);

    // Resetting lockout restores ability to unlock
    await resetPinLockout();
    await expect(unlockWithPin('5678')).resolves.toBeDefined();
    expect(await isUnlocked()).toBe(true);
  });

  it('removes PIN and clears storage', async () => {
    await createVault('master-password-123');
    await setupPin('9876');
    expect(await hasPin()).toBe(true);

    await removePin();
    expect(await hasPin()).toBe(false);
  });
});
