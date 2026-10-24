/**
 * Account helpers shared by the vault, importers and UI: validation,
 * normalization, de-duplication and merging.
 */
import type { AccountEntry, ImportedAccount, VaultData } from './types';
import {
  DEFAULT_ALGORITHM,
  DEFAULT_DIGITS,
  DEFAULT_PERIOD,
  isValidBase32,
  normalizeBase32,
  parseAlgorithm,
  parseDigits,
  parsePeriod,
} from '../crypto/totp';
import { normalizeDomain } from './match';

export function newId(): string {
  return crypto.randomUUID();
}

function cleanText(value: unknown, max = 256): string {
  return typeof value === 'string' ? value.trim().slice(0, max) : '';
}

function cleanDomains(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const out = new Set<string>();
  for (const item of value) {
    const domain = typeof item === 'string' ? normalizeDomain(item) : null;
    if (domain) {
      out.add(domain);
    }
  }
  return [...out];
}

/**
 * Validates an imported or edited account and fills defaults. Returns a
 * human readable error string when the data cannot produce working codes.
 */
export function validateImported(input: Partial<ImportedAccount>): ImportedAccount | string {
  const secret = normalizeBase32(cleanText(input.secret, 1024));
  if (!isValidBase32(secret)) {
    return 'The secret key is missing or is not valid Base32.';
  }
  const algorithm = input.algorithm ? parseAlgorithm(input.algorithm) : DEFAULT_ALGORITHM;
  if (!algorithm) {
    return `Unsupported algorithm "${String(input.algorithm)}".`;
  }
  const digits = input.digits === undefined ? DEFAULT_DIGITS : parseDigits(input.digits);
  if (!digits) {
    return `Unsupported digit count "${String(input.digits)}".`;
  }
  const period = input.period === undefined ? DEFAULT_PERIOD : parsePeriod(input.period);
  if (!period) {
    return `Invalid period "${String(input.period)}".`;
  }
  const type = input.type === 'hotp' ? 'hotp' : 'totp';
  const counter = Number(input.counter ?? 0);
  if (!Number.isSafeInteger(counter) || counter < 0) {
    return 'The HOTP counter must be a non-negative integer.';
  }
  const issuer = cleanText(input.issuer);
  const label = cleanText(input.label);
  if (!issuer && !label) {
    return 'An issuer or account name is required.';
  }
  return {
    type,
    issuer,
    label,
    secret,
    algorithm,
    digits,
    period,
    counter,
    domains: cleanDomains(input.domains),
    pinned: Boolean(input.pinned),
  };
}

/** Builds a full vault entry from importer output. */
export function createAccount(imported: ImportedAccount, now: number = Date.now()): AccountEntry {
  return {
    ...imported,
    id: newId(),
    domains: cleanDomains(imported.domains),
    pinned: Boolean(imported.pinned),
    createdAt: now,
    updatedAt: now,
  };
}

/** Defensive parse of an entry read back from decrypted storage. */
export function sanitizeAccount(raw: unknown): AccountEntry | null {
  if (!raw || typeof raw !== 'object') {
    return null;
  }
  const entry = raw as Partial<AccountEntry>;
  const valid = validateImported(entry);
  if (typeof valid === 'string') {
    return null;
  }
  const now = Date.now();
  return {
    ...valid,
    id: typeof entry.id === 'string' && entry.id ? entry.id : newId(),
    domains: cleanDomains(entry.domains),
    pinned: Boolean(entry.pinned),
    createdAt: typeof entry.createdAt === 'number' ? entry.createdAt : now,
    updatedAt: typeof entry.updatedAt === 'number' ? entry.updatedAt : now,
  };
}

/** Identity used for duplicate detection: same secret and same parameters means same account. */
export function fingerprint(account: Pick<AccountEntry, 'secret' | 'type' | 'algorithm' | 'digits' | 'period'>): string {
  return [normalizeBase32(account.secret), account.type, account.algorithm, account.digits, account.period].join('|');
}

export interface MergeResult {
  data: VaultData;
  added: AccountEntry[];
  duplicates: number;
}

/**
 * Non-destructive merge: appends accounts that are not already present and
 * never removes or overwrites existing ones. Domains of duplicates are unioned.
 */
export function mergeAccounts(data: VaultData, incoming: readonly (ImportedAccount | AccountEntry)[]): MergeResult {
  const index = new Map<string, AccountEntry>();
  for (const account of data.accounts) {
    index.set(fingerprint(account), account);
  }
  const added: AccountEntry[] = [];
  let duplicates = 0;
  const now = Date.now();
  for (const candidate of incoming) {
    const key = fingerprint(candidate);
    const existing = index.get(key);
    if (existing) {
      duplicates += 1;
      const extra = cleanDomains(candidate.domains).filter((d) => !existing.domains.includes(d));
      if (extra.length > 0) {
        existing.domains = [...existing.domains, ...extra];
        existing.updatedAt = now;
      }
      continue;
    }
    const account = 'id' in candidate ? { ...candidate, id: newId(), updatedAt: now } : createAccount(candidate, now);
    index.set(key, account);
    added.push(account);
  }
  return { data: { ...data, accounts: [...data.accounts, ...added] }, added, duplicates };
}

/** Display name used across the UI. */
export function displayName(account: Pick<AccountEntry, 'issuer' | 'label'>): string {
  return account.issuer || account.label || 'Unnamed account';
}

/**
 * Sorts accounts: pinned accounts first, followed by unpinned accounts.
 * Stable ordering is preserved within each group.
 */
export function sortAccounts(accounts: readonly AccountEntry[]): AccountEntry[] {
  const pinned: AccountEntry[] = [];
  const normal: AccountEntry[] = [];
  for (const account of accounts) {
    if (account.pinned) {
      pinned.push(account);
    } else {
      normal.push(account);
    }
  }
  return [...pinned, ...normal];
}
