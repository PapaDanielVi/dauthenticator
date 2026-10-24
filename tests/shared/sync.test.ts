import { beforeEach, describe, expect, it } from 'vitest';
import {
  clearSync,
  getSyncStatus,
  mergeFromSync,
  pushVaultToSync,
  readSyncedVault,
} from '../../src/shared/sync';
import { createVault, updateVault } from '../../src/crypto/vault';
import { mockLocal, mockSession, mockSync } from '../setup/chromeMock';

describe('Chrome Storage Sync Failsafe', () => {
  beforeEach(async () => {
    await mockLocal.clear();
    await mockSession.clear();
    await mockSync.clear();
  });

  it('pushes encrypted vault in chunks and verifies integrity', async () => {
    await createVault('sync-password-test');

    // Add several accounts to exceed chunk size if needed
    await updateVault((data) => {
      for (let i = 0; i < 20; i++) {
        data.accounts.push({
          id: `acc-sync-${i}`,
          type: 'totp',
          issuer: `Service ${i}`,
          label: `user${i}@example.com`,
          secret: 'JBSWY3DPEHPK3PXP',
          algorithm: 'SHA-1',
          digits: 6,
          period: 30,
          counter: 0,
          domains: [`service${i}.com`],
          createdAt: 1000,
          updatedAt: 1000,
        });
      }
      return data;
    });

    const meta = await pushVaultToSync();
    expect(meta.chunks).toBeGreaterThanOrEqual(1);
    expect(meta.sha256).toMatch(/^[0-9a-f]{64}$/);

    const synced = await readSyncedVault();
    expect(synced).not.toBeNull();
    expect(synced?.envelope.version).toBe(1);

    const status = await getSyncStatus();
    expect(status.meta?.sha256).toBe(meta.sha256);
  });

  it('merges synced accounts non-destructively', async () => {
    await createVault('shared-sync-password');

    await updateVault((data) => {
      data.accounts.push({
        id: 'acc-original',
        type: 'totp',
        issuer: 'PrimaryService',
        label: 'user1',
        secret: 'JBSWY3DPEHPK3PXP',
        algorithm: 'SHA-1',
        digits: 6,
        period: 30,
        counter: 0,
        domains: ['primary.com'],
        createdAt: 1000,
        updatedAt: 1000,
      });
      return data;
    });

    await pushVaultToSync();

    // Now modify local vault (simulate local added account and changed domain)
    await updateVault((data) => {
      data.accounts.push({
        id: 'acc-local-only',
        type: 'totp',
        issuer: 'LocalOnlyService',
        label: 'user2',
        secret: 'JBSWY3DPEHPK3PXP',
        algorithm: 'SHA-256',
        digits: 8,
        period: 60,
        counter: 0,
        domains: ['local.com'],
        createdAt: 2000,
        updatedAt: 2000,
      });
      return data;
    });

    // Merge from sync: remote PrimaryService should not duplicate, local LocalOnlyService should be preserved
    const mergeResult = await mergeFromSync();
    expect(mergeResult.data.accounts.length).toBe(2);
    expect(mergeResult.duplicates).toBe(1); // PrimaryService already existed

    await clearSync();
    const afterClear = await readSyncedVault();
    expect(afterClear).toBeNull();
  });
});
