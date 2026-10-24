/**
 * Higher level vault operations used by the popup, options page and service
 * worker. Every mutation goes through updateVault so it is re-encrypted with a
 * fresh IV and serialized against concurrent edits from the same context.
 */
import { updateVault } from '../crypto/vault';
import { generateHotp } from '../crypto/totp';
import { mergeAccounts, validateImported, type MergeResult } from './accounts';
import { normalizeDomain } from './match';
import type { AccountEntry, ImportedAccount } from './types';

/** Adds imported accounts, skipping duplicates. */
export async function addAccounts(incoming: readonly ImportedAccount[]): Promise<MergeResult> {
  const holder: { result?: MergeResult } = {};
  await updateVault((data) => {
    holder.result = mergeAccounts(data, incoming);
    return holder.result.data;
  });
  if (!holder.result) {
    throw new Error('Saving the accounts failed.');
  }
  return holder.result;
}

export async function deleteAccount(id: string): Promise<void> {
  await updateVault((data) => ({ ...data, accounts: data.accounts.filter((a) => a.id !== id) }));
}

export type AccountPatch = Partial<Pick<AccountEntry, 'issuer' | 'label' | 'domains' | 'secret' | 'algorithm' | 'digits' | 'period' | 'counter' | 'type' | 'pinned'>>;

/** Applies an edit after re-validating the resulting account. */
export async function editAccount(id: string, patch: AccountPatch): Promise<AccountEntry> {
  const holder: { updated?: AccountEntry } = {};
  await updateVault((data) => {
    const index = data.accounts.findIndex((a) => a.id === id);
    const current = data.accounts[index];
    if (!current) {
      throw new Error('That account no longer exists.');
    }
    const valid = validateImported({ ...current, ...patch });
    if (typeof valid === 'string') {
      throw new Error(valid);
    }
    const next: AccountEntry = { ...current, ...valid, domains: valid.domains ?? [], updatedAt: Date.now() };
    data.accounts[index] = next;
    holder.updated = next;
    return data;
  });
  if (!holder.updated) {
    throw new Error('That account no longer exists.');
  }
  return holder.updated;
}

/** Moves an account one step up or down in the list. */
export async function moveAccount(id: string, direction: -1 | 1): Promise<void> {
  await updateVault((data) => {
    const index = data.accounts.findIndex((a) => a.id === id);
    const target = index + direction;
    if (index < 0 || target < 0 || target >= data.accounts.length) {
      return data;
    }
    const accounts = [...data.accounts];
    const [item] = accounts.splice(index, 1);
    if (item) {
      accounts.splice(target, 0, item);
    }
    return { ...data, accounts };
  });
}

/**
 * Produces the next HOTP code and persists counter + 1, so the same code is
 * never shown twice.
 */
export async function consumeHotp(id: string): Promise<string> {
  const holder: { used?: AccountEntry } = {};
  await updateVault((data) => {
    const account = data.accounts.find((a) => a.id === id);
    if (!account || account.type !== 'hotp') {
      throw new Error('HOTP account not found.');
    }
    holder.used = { ...account };
    account.counter += 1;
    account.updatedAt = Date.now();
    return data;
  });
  const used = holder.used;
  if (!used) {
    throw new Error('HOTP account not found.');
  }
  return generateHotp({ secret: used.secret, algorithm: used.algorithm, digits: used.digits }, used.counter);
}

/** Remembers that an account belongs to a hostname, for future autofill matching. */
export async function rememberDomain(id: string, hostname: string): Promise<void> {
  const domain = normalizeDomain(hostname);
  if (!domain) {
    return;
  }
  await updateVault((data) => {
    const account = data.accounts.find((a) => a.id === id);
    if (account && !account.domains.includes(domain)) {
      account.domains = [...account.domains, domain];
      account.updatedAt = Date.now();
    }
    return data;
  });
}

/** Toggles whether an account is pinned at the top of the list. */
export async function togglePinAccount(id: string): Promise<boolean> {
  const holder: { pinned?: boolean } = {};
  await updateVault((data) => {
    const account = data.accounts.find((a) => a.id === id);
    if (!account) {
      throw new Error('That account no longer exists.');
    }
    account.pinned = !account.pinned;
    account.updatedAt = Date.now();
    holder.pinned = account.pinned;
    return data;
  });
  return Boolean(holder.pinned);
}
