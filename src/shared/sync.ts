/**
 * Failsafe copy of the encrypted vault in chrome.storage.sync.
 *
 * The envelope pushed here is exactly what lives in chrome.storage.local, so it
 * stays encrypted under the master password end to end. chrome.storage.sync
 * limits each item to 8 KB, so the serialized envelope is split into chunks and
 * reassembled on read, with a SHA-256 checksum to catch partially synced data.
 * Restoring is a merge: remote accounts are added, local ones are never removed.
 */
import { decryptWithPassword, decryptWithSession, getEncryptedVault, isEncryptedVault, updateVault, WrongPasswordError } from '../crypto/vault';
import type { EncryptedVault } from '../crypto/vault';
import { bytesToHex, utf8Encode } from '../crypto/encoding';
import { mergeAccounts, sanitizeAccount, type MergeResult } from './accounts';
import { PasswordRequiredError } from './errors';
import { updateSettings } from './settings';
import type { AccountEntry, VaultData } from './types';

export const SYNC_META_KEY = 'dauth.sync.meta';
export const SYNC_CHUNK_PREFIX = 'dauth.sync.chunk.';
/** Characters per chunk. Leaves headroom under the 8192 byte per-item quota for the key and JSON quoting. */
export const SYNC_CHUNK_SIZE = 7000;
const SYNC_FORMAT = 1;
const SYNC_QUOTA_FALLBACK = 102_400;

export interface SyncMeta {
  format: number;
  chunks: number;
  length: number;
  sha256: string;
  updatedAt: number;
}

export interface SyncStatus {
  meta: SyncMeta | null;
  bytesInUse: number;
  quotaBytes: number;
}

function chunkKey(index: number): string {
  return `${SYNC_CHUNK_PREFIX}${index}`;
}

async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', utf8Encode(text));
  return bytesToHex(new Uint8Array(digest));
}

function quotaBytes(): number {
  return chrome.storage.sync.QUOTA_BYTES ?? SYNC_QUOTA_FALLBACK;
}

async function readMeta(): Promise<SyncMeta | null> {
  const stored = await chrome.storage.sync.get(SYNC_META_KEY);
  const meta = stored[SYNC_META_KEY] as SyncMeta | undefined;
  return meta && meta.format === SYNC_FORMAT && Number.isInteger(meta.chunks) ? meta : null;
}

/** Writes the current encrypted vault to chrome.storage.sync. */
export async function pushVaultToSync(): Promise<SyncMeta> {
  const envelope = await getEncryptedVault();
  if (!envelope) {
    throw new Error('There is no vault to back up yet.');
  }
  const serialized = JSON.stringify(envelope);
  const items: Record<string, unknown> = {};
  let estimatedBytes = 0;
  let count = 0;
  for (let offset = 0; offset < serialized.length; offset += SYNC_CHUNK_SIZE) {
    const key = chunkKey(count);
    const value = serialized.slice(offset, offset + SYNC_CHUNK_SIZE);
    items[key] = value;
    estimatedBytes += key.length + JSON.stringify(value).length;
    count += 1;
  }
  const meta: SyncMeta = {
    format: SYNC_FORMAT,
    chunks: count,
    length: serialized.length,
    sha256: await sha256Hex(serialized),
    updatedAt: Date.now(),
  };
  items[SYNC_META_KEY] = meta;
  estimatedBytes += SYNC_META_KEY.length + JSON.stringify(meta).length;

  if (estimatedBytes > quotaBytes()) {
    const message = `The vault (${Math.ceil(estimatedBytes / 1024)} KB) exceeds the Chrome Sync quota. Use encrypted file backups instead.`;
    await updateSettings({ lastSyncError: message });
    throw new Error(message);
  }

  const previous = await readMeta();
  try {
    await chrome.storage.sync.set(items);
    if (previous && previous.chunks > count) {
      const stale = Array.from({ length: previous.chunks - count }, (_, i) => chunkKey(count + i));
      await chrome.storage.sync.remove(stale);
    }
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    await updateSettings({ lastSyncError: message });
    throw error;
  }
  await updateSettings({ lastSyncAt: meta.updatedAt, lastSyncError: null });
  return meta;
}

/** Reassembles and integrity-checks the encrypted vault stored in sync. */
export async function readSyncedVault(): Promise<{ envelope: EncryptedVault; meta: SyncMeta } | null> {
  const meta = await readMeta();
  if (!meta) {
    return null;
  }
  const keys = Array.from({ length: meta.chunks }, (_, i) => chunkKey(i));
  const stored = await chrome.storage.sync.get(keys);
  let serialized = '';
  for (const key of keys) {
    const part = stored[key];
    if (typeof part !== 'string') {
      throw new Error('The Chrome Sync backup is incomplete. It may still be syncing, try again shortly.');
    }
    serialized += part;
  }
  if (serialized.length !== meta.length || (await sha256Hex(serialized)) !== meta.sha256) {
    throw new Error('The Chrome Sync backup failed its integrity check. It may still be syncing, try again shortly.');
  }
  const envelope: unknown = JSON.parse(serialized);
  if (!isEncryptedVault(envelope)) {
    throw new Error('The Chrome Sync backup has an unexpected format.');
  }
  return { envelope, meta };
}

export async function getSyncStatus(): Promise<SyncStatus> {
  const [meta, bytesInUse] = await Promise.all([readMeta(), chrome.storage.sync.getBytesInUse(null)]);
  return { meta, bytesInUse, quotaBytes: quotaBytes() };
}

/** Removes every DAuthenticator key from chrome.storage.sync. */
export async function clearSync(): Promise<void> {
  const all = await chrome.storage.sync.get(null);
  const keys = Object.keys(all).filter((k) => k === SYNC_META_KEY || k.startsWith(SYNC_CHUNK_PREFIX));
  if (keys.length > 0) {
    await chrome.storage.sync.remove(keys);
  }
}

/**
 * Merges the synced vault into the local one. If the synced copy was written
 * with the same password and salt, the session key is enough. Otherwise the
 * caller must supply the password that protected it.
 */
export async function mergeFromSync(password?: string): Promise<MergeResult> {
  const remote = await readSyncedVault();
  if (!remote) {
    throw new Error('No DAuthenticator backup was found in Chrome Sync.');
  }
  let data = await decryptWithSession<VaultData>(remote.envelope);
  if (!data) {
    if (!password) {
      throw new PasswordRequiredError('sync');
    }
    try {
      data = await decryptWithPassword<VaultData>(remote.envelope, password);
    } catch (error) {
      if (error instanceof WrongPasswordError) {
        throw new PasswordRequiredError('sync', true);
      }
      throw error;
    }
  }
  const incoming = (Array.isArray(data.accounts) ? data.accounts : [])
    .map((raw) => sanitizeAccount(raw))
    .filter((a): a is AccountEntry => a !== null);

  const holder: { result?: MergeResult } = {};
  await updateVault((current) => {
    holder.result = mergeAccounts(current, incoming);
    return holder.result.data;
  });
  if (!holder.result) {
    throw new Error('Merge did not run.');
  }
  return holder.result;
}
