/**
 * Fallback mapper for unencrypted JSON and CSV exports from apps without a
 * dedicated importer (Authy exports made with third party tools, LastPass
 * Authenticator, Proton Authenticator, Raivo, Ente, password manager dumps).
 *
 * It looks for objects (or CSV rows) that carry either an otpauth:// URI or a
 * Base32 secret under a familiar key, and maps the surrounding keys onto the
 * AccountEntry fields.
 */
import type { ImportedAccount } from '../shared/types';
import { validateImported } from '../shared/accounts';
import { normalizeDomain } from '../shared/match';
import { isValidBase32 } from '../crypto/totp';
import { isOtpAuthUri, parseOtpAuthUri } from './otpauthUri';
import { ImportCollector, type ImportResult } from './types';

const MAX_DEPTH = 8;
const MAX_FLATTEN_DEPTH = 3;

function aliases(...keys: string[]): ReadonlySet<string> {
  return new Set(keys);
}

const SECRET_KEYS = aliases(
  'secret', 'totp', 'totpsecret', 'seed', 'secretkey', 'otpsecret', 'sharedsecret', 'logintotp', 'base32',
  'mfasecret', 'twofactorsecret', 'authenticatorkey', 'otpkey', 'totpkey',
);
/** Generic names that only count as a secret when the value looks like a real seed. */
const WEAK_SECRET_KEYS = aliases('key', 'otp', 'token');
const MIN_WEAK_SECRET_LENGTH = 16;
const ISSUER_KEYS = aliases(
  'issuer', 'issuername', 'originalissuername', 'service', 'servicename', 'provider', 'site', 'website', 'app',
);
const NAME_KEYS = aliases('name', 'title', 'displayname');
const ACCOUNT_KEYS = aliases(
  'account', 'accountname', 'username', 'user', 'email', 'login', 'label', 'loginusername', 'originalusername',
);
const DIGIT_KEYS = aliases('digits', 'digit', 'codelength', 'length', 'tokenlength');
const PERIOD_KEYS = aliases('period', 'timestep', 'interval', 'timer', 'step', 'refresh', 'duration');
const ALGORITHM_KEYS = aliases('algorithm', 'algo', 'hash', 'hmac', 'hashalgorithm', 'digest');
const TYPE_KEYS = aliases('type', 'kind', 'tokentype', 'otptype', 'entrytype');
const COUNTER_KEYS = aliases('counter', 'count', 'hotpcounter');
const URL_KEYS = aliases('url', 'uri', 'loginuri', 'domain', 'host', 'hostname', 'website', 'site');

const UNSUPPORTED_TYPES = new Set(['steam', 'motp', 'yandex', 'yaotp', 'battle', 'blizzard']);

function normalizeKey(key: string): string {
  return key.toLowerCase().replace(/[^a-z0-9]/g, '');
}

/** Flattens nested objects to leaf values keyed by normalized leaf name. Shallow keys win. */
function flatten(record: Record<string, unknown>): Map<string, unknown> {
  const out = new Map<string, unknown>();
  const queue: Array<{ node: Record<string, unknown>; depth: number }> = [{ node: record, depth: 0 }];
  while (queue.length > 0) {
    const { node, depth } = queue.shift() as { node: Record<string, unknown>; depth: number };
    for (const [key, value] of Object.entries(node)) {
      const normalized = normalizeKey(key);
      if (value && typeof value === 'object' && !Array.isArray(value)) {
        if (depth < MAX_FLATTEN_DEPTH) {
          queue.push({ node: value as Record<string, unknown>, depth: depth + 1 });
        }
        continue;
      }
      if (Array.isArray(value)) {
        // Arrays of URI objects, as in Bitwarden's login.uris.
        const first = value.find((v) => v && typeof v === 'object') as Record<string, unknown> | undefined;
        if (first && depth < MAX_FLATTEN_DEPTH) {
          queue.push({ node: first, depth: depth + 1 });
        }
        continue;
      }
      if (!out.has(normalized)) {
        out.set(normalized, value);
      }
    }
  }
  return out;
}

function pick(fields: Map<string, unknown>, keys: ReadonlySet<string>): unknown {
  for (const [key, value] of fields) {
    if (keys.has(key) && value !== null && value !== undefined && value !== '') {
      return value;
    }
  }
  return undefined;
}

function pickString(fields: Map<string, unknown>, keys: ReadonlySet<string>): string {
  const value = pick(fields, keys);
  return typeof value === 'string' || typeof value === 'number' ? String(value).trim() : '';
}

function findUri(fields: Map<string, unknown>): string | null {
  for (const value of fields.values()) {
    if (typeof value === 'string' && isOtpAuthUri(value)) {
      return value.trim();
    }
  }
  return null;
}

function domainHints(fields: Map<string, unknown>): string[] {
  const out: string[] = [];
  for (const [key, value] of fields) {
    if (URL_KEYS.has(key) && typeof value === 'string' && !isOtpAuthUri(value)) {
      const domain = normalizeDomain(value);
      if (domain) {
        out.push(domain);
      }
    }
  }
  return out;
}

/**
 * Maps one flat record. Returns null when the record has nothing secret-like,
 * an error string when it does but cannot be used.
 */
export function mapFields(fields: Map<string, unknown>): ImportedAccount | string | null {
  const domains = domainHints(fields);
  const uri = findUri(fields);
  if (uri) {
    try {
      const parsed = parseOtpAuthUri(uri);
      if (!parsed.issuer) {
        parsed.issuer = pickString(fields, ISSUER_KEYS) || pickString(fields, NAME_KEYS);
      }
      return { ...parsed, domains: [...(parsed.domains ?? []), ...domains] };
    } catch (error) {
      return error instanceof Error ? error.message : String(error);
    }
  }

  let rawSecret = pickString(fields, SECRET_KEYS);
  if (!rawSecret) {
    const weak = pickString(fields, WEAK_SECRET_KEYS);
    if (weak.replace(/[\s=-]/g, '').length >= MIN_WEAK_SECRET_LENGTH && isValidBase32(weak)) {
      rawSecret = weak;
    }
  }
  if (!rawSecret) {
    return null;
  }
  if (/^steam:\/\//i.test(rawSecret)) {
    return 'Steam Guard codes are not supported.';
  }
  if (!isValidBase32(rawSecret)) {
    // Keys like "key" or "token" are common in unrelated data, so stay quiet.
    return null;
  }

  const typeValue = pickString(fields, TYPE_KEYS).toLowerCase();
  if (UNSUPPORTED_TYPES.has(typeValue)) {
    return `${typeValue} tokens are not supported.`;
  }
  const issuer = pickString(fields, ISSUER_KEYS);
  const name = pickString(fields, NAME_KEYS);
  const account = pickString(fields, ACCOUNT_KEYS);
  const digits = pickString(fields, DIGIT_KEYS);
  const period = pickString(fields, PERIOD_KEYS);
  const algorithm = pickString(fields, ALGORITHM_KEYS);
  const counter = pickString(fields, COUNTER_KEYS);

  return validateImported({
    type: typeValue === 'hotp' ? 'hotp' : 'totp',
    issuer: issuer || name,
    label: account || (issuer ? name : ''),
    secret: rawSecret,
    algorithm: (algorithm || undefined) as ImportedAccount['algorithm'] | undefined,
    digits: (digits ? Number(digits) : undefined) as ImportedAccount['digits'] | undefined,
    period: period ? Number(period) : undefined,
    counter: counter ? Number(counter) : undefined,
    domains,
  });
}

function contextName(record: Record<string, unknown>, index: number): string {
  const fields = flatten(record);
  return pickString(fields, ISSUER_KEYS) || pickString(fields, NAME_KEYS) || `Entry ${index + 1}`;
}

/** Walks arbitrary JSON and maps every object that looks like an OTP account. */
export function importGenericJson(root: unknown): ImportResult {
  const collector = new ImportCollector();
  let counter = 0;

  const visit = (node: unknown, depth: number): void => {
    if (depth > MAX_DEPTH || node === null || node === undefined) {
      return;
    }
    if (typeof node === 'string') {
      if (isOtpAuthUri(node)) {
        counter += 1;
        try {
          collector.add(parseOtpAuthUri(node), `Entry ${counter}`);
        } catch (error) {
          collector.warn(`Entry ${counter}: ${error instanceof Error ? error.message : String(error)}`);
        }
      }
      return;
    }
    if (Array.isArray(node)) {
      node.forEach((child) => visit(child, depth + 1));
      return;
    }
    if (typeof node === 'object') {
      const record = node as Record<string, unknown>;
      const mapped = mapFields(flatten(record));
      if (mapped !== null) {
        collector.add(mapped, contextName(record, counter));
        counter += 1;
        return;
      }
      Object.values(record).forEach((child) => visit(child, depth + 1));
    }
  };

  visit(root, 0);
  return collector.finish('generic-json');
}

/** Maps CSV rows (already keyed by header) using the same heuristics. */
export function importGenericCsvRecords(records: readonly Record<string, string>[]): ImportResult {
  const collector = new ImportCollector();
  records.forEach((record, index) => {
    const mapped = mapFields(flatten(record));
    if (mapped === null) {
      collector.warn(`Row ${index + 2}: no OTP secret found.`);
      return;
    }
    collector.add(mapped, `Row ${index + 2}`);
  });
  return collector.finish('generic-csv');
}

/** True when a CSV header row contains at least one column the mapper understands as a secret. */
export function csvHeaderLooksUsable(headers: readonly string[]): boolean {
  return headers.some((h) => SECRET_KEYS.has(normalizeKey(h)) || WEAK_SECRET_KEYS.has(normalizeKey(h)));
}
