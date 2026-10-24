/**
 * Export helpers for encrypted and plaintext backups.
 */
import { getEncryptedVault, loadVault, verifyPassword } from '../crypto/vault';
import { toOtpAuthUri } from '../importers/otpauthUri';
import { DAUTH_APP_ID, DAUTH_ENCRYPTED_KIND, DAUTH_PLAIN_KIND, type DAuthBackupFile } from '../importers/fileImporters';
import type { AccountEntry } from './types';

export function downloadBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => {
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, 1000);
}

export function downloadText(content: string, filename: string, mimeType = 'application/json'): void {
  const blob = new Blob([content], { type: mimeType });
  downloadBlob(blob, filename);
}

function timestampSuffix(): string {
  const d = new Date();
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}_${pad(d.getHours())}${pad(d.getMinutes())}`;
}

/** Exports the vault in its encrypted state. Zero password prompt needed. */
export async function exportEncryptedBackup(extension: 'enc' | 'json' = 'enc'): Promise<void> {
  const envelope = await getEncryptedVault();
  if (!envelope) {
    throw new Error('No vault to export.');
  }
  const payload: DAuthBackupFile = {
    app: DAUTH_APP_ID,
    kind: DAUTH_ENCRYPTED_KIND,
    exportedAt: new Date().toISOString(),
    vault: envelope,
  };
  const filename = extension === 'json'
    ? `dauthenticator_encrypted_${timestampSuffix()}.json`
    : `dauthenticator_backup_${timestampSuffix()}.enc`;
  downloadText(JSON.stringify(payload, null, 2), filename, 'application/json');
}

/** Plaintext JSON export. Requires master password verification. */
export async function exportPlainJsonBackup(passwordConfirm: string): Promise<void> {
  const ok = await verifyPassword(passwordConfirm);
  if (!ok) {
    throw new Error('Master password confirmation was incorrect.');
  }
  const vault = await loadVault();
  const payload: DAuthBackupFile = {
    app: DAUTH_APP_ID,
    kind: DAUTH_PLAIN_KIND,
    exportedAt: new Date().toISOString(),
    accounts: vault.accounts,
  };
  const filename = `dauthenticator_plain_${timestampSuffix()}.json`;
  downloadText(JSON.stringify(payload, null, 2), filename, 'application/json');
}

/** Plaintext URI list (.txt). Requires master password verification. */
export async function exportPlainUriList(passwordConfirm: string): Promise<void> {
  const ok = await verifyPassword(passwordConfirm);
  if (!ok) {
    throw new Error('Master password confirmation was incorrect.');
  }
  const vault = await loadVault();
  const lines = vault.accounts.map((a: AccountEntry) => toOtpAuthUri(a));
  const filename = `dauthenticator_uris_${timestampSuffix()}.txt`;
  downloadText(lines.join('\n'), filename, 'text/plain');
}
