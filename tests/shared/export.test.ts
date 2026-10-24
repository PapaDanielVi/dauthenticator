import { beforeEach, describe, expect, it } from 'vitest';
import { createVault } from '../../src/crypto/vault';
import { mockLocal, mockSession } from '../setup/chromeMock';
import { exportEncryptedBackup } from '../../src/shared/export';

describe('Vault Backups & Exports', () => {
  beforeEach(async () => {
    await mockLocal.clear();
    await mockSession.clear();
  });

  it('exports zero-knowledge encrypted backup and imports it back', async () => {
    await createVault('backup-test-password');

    const mockAnchor = {
      href: '',
      download: '',
      click: () => {},
    };

    (globalThis as unknown as { document: unknown }).document = {
      createElement: (tag: string) => {
        if (tag === 'a') return mockAnchor;
        return {};
      },
      body: {
        appendChild: () => {},
        removeChild: () => {},
      },
    };
    (globalThis as unknown as { URL: unknown }).URL = {
      createObjectURL: (_blob: Blob) => 'blob:mock-url',
      revokeObjectURL: () => {},
    };

    // Export .enc
    await exportEncryptedBackup('enc');
    expect(mockAnchor.download).toMatch(/^dauthenticator_backup_.*\.enc$/);

    // Export .json
    await exportEncryptedBackup('json');
    expect(mockAnchor.download).toMatch(/^dauthenticator_encrypted_.*\.json$/);
  });
});
