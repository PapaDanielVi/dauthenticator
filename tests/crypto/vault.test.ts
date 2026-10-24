import { beforeEach, describe, expect, it } from 'vitest';
import {
  changePassword,
  createVault,
  destroyVault,
  getEncryptedVault,
  hasVault,
  isUnlocked,
  loadVault,
  lockVault,
  unlockVault,
  updateVault,
  verifyPassword,
  WrongPasswordError,
  VaultLockedError,
} from '../../src/crypto/vault';
import { mockLocal, mockSession } from '../setup/chromeMock';

describe('Vault Cryptography & Persistence', () => {
  beforeEach(async () => {
    await mockLocal.clear();
    await mockSession.clear();
  });

  it('creates an encrypted vault and caches session key', async () => {
    expect(await hasVault()).toBe(false);

    await createVault('super-secret-password-123');

    expect(await hasVault()).toBe(true);
    expect(await isUnlocked()).toBe(true);

    const envelope = await getEncryptedVault();
    expect(envelope).not.toBeNull();
    expect(envelope?.version).toBe(1);
    expect(typeof envelope?.ciphertext).toBe('string');
    expect(typeof envelope?.salt).toBe('string');
    expect(typeof envelope?.iv).toBe('string');

    // Ciphertext must not contain plaintext account data or password
    expect(envelope?.ciphertext).not.toContain('super-secret-password');
    expect(envelope?.ciphertext).not.toContain('accounts');
  });

  it('locks the vault and unlocks with correct password', async () => {
    await createVault('mypassword456');
    expect(await isUnlocked()).toBe(true);

    await lockVault();
    expect(await isUnlocked()).toBe(false);

    await expect(loadVault()).rejects.toThrow(VaultLockedError);

    // Wrong password fails
    await expect(unlockVault('wrong-pass')).rejects.toThrow(WrongPasswordError);
    expect(await isUnlocked()).toBe(false);

    // Correct password succeeds
    const data = await unlockVault('mypassword456');
    expect(data.version).toBe(1);
    expect(data.accounts).toEqual([]);
    expect(await isUnlocked()).toBe(true);
  });

  it('updates vault accounts with read-modify-write queue', async () => {
    await createVault('correct-horse-battery-staple');

    await updateVault((data) => {
      data.accounts.push({
        id: 'acc-1',
        type: 'totp',
        issuer: 'GitHub',
        label: 'user@github.com',
        secret: 'JBSWY3DPEHPK3PXP',
        algorithm: 'SHA-1',
        digits: 6,
        period: 30,
        counter: 0,
        domains: ['github.com'],
        pinned: true,
        createdAt: 1000,
        updatedAt: 1000,
      });
      return data;
    });

    const loaded = await loadVault();
    expect(loaded.accounts.length).toBe(1);
    expect(loaded.accounts[0]?.issuer).toBe('GitHub');
    expect(loaded.accounts[0]?.pinned).toBe(true);

    // Lock and unlock to verify persistence across sessions
    await lockVault();
    const fresh = await unlockVault('correct-horse-battery-staple');
    expect(fresh.accounts.length).toBe(1);
    expect(fresh.accounts[0]?.issuer).toBe('GitHub');
  });

  it('changes master password and re-encrypts stored data', async () => {
    await createVault('initial-pass-123');

    await updateVault((data) => {
      data.accounts.push({
        id: 'acc-2',
        type: 'totp',
        issuer: 'AWS',
        label: 'admin',
        secret: 'JBSWY3DPEHPK3PXP',
        algorithm: 'SHA-256',
        digits: 8,
        period: 60,
        counter: 0,
        domains: [],
        createdAt: 2000,
        updatedAt: 2000,
      });
      return data;
    });

    await changePassword('initial-pass-123', 'new-super-secure-pass-789');

    // Old password fails
    expect(await verifyPassword('initial-pass-123')).toBe(false);

    // New password verifies
    expect(await verifyPassword('new-super-secure-pass-789')).toBe(true);

    await lockVault();
    const unlocked = await unlockVault('new-super-secure-pass-789');
    expect(unlocked.accounts.length).toBe(1);
    expect(unlocked.accounts[0]?.issuer).toBe('AWS');
  });

  it('destroys vault and wipes local storage', async () => {
    await createVault('password-to-destroy');
    expect(await hasVault()).toBe(true);

    await destroyVault();
    expect(await hasVault()).toBe(false);
    expect(await isUnlocked()).toBe(false);
  });
});
