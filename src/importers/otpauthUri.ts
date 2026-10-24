/**
 * Parser and serializer for Key Uri Format links:
 * otpauth://TYPE/LABEL?secret=SECRET&issuer=ISSUER&algorithm=SHA1&digits=6&period=30&counter=0
 */
import type { AccountEntry, ImportedAccount } from '../shared/types';
import { validateImported } from '../shared/accounts';
import { DEFAULT_ALGORITHM, DEFAULT_DIGITS, DEFAULT_PERIOD } from '../crypto/totp';

const OTPAUTH_PREFIX = 'otpauth://';
const ALGORITHM_PARAM: Record<AccountEntry['algorithm'], string> = {
  'SHA-1': 'SHA1',
  'SHA-256': 'SHA256',
  'SHA-512': 'SHA512',
};

function safeDecode(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export function isOtpAuthUri(value: string): boolean {
  return value.trim().toLowerCase().startsWith(OTPAUTH_PREFIX);
}

/** Parses one otpauth:// URI. Throws with a readable message when it is unusable. */
export function parseOtpAuthUri(input: string): ImportedAccount {
  const uri = input.trim();
  if (!isOtpAuthUri(uri)) {
    throw new Error('Not an otpauth:// link.');
  }
  const rest = uri.slice(OTPAUTH_PREFIX.length);
  const slash = rest.indexOf('/');
  if (slash < 0) {
    throw new Error('The otpauth link is missing its label.');
  }
  const typeRaw = rest.slice(0, slash).toLowerCase();
  if (typeRaw !== 'totp' && typeRaw !== 'hotp') {
    throw new Error(`Unsupported OTP type "${typeRaw}". Only TOTP and HOTP are supported.`);
  }
  const afterType = rest.slice(slash + 1);
  const queryStart = afterType.indexOf('?');
  const rawLabel = queryStart >= 0 ? afterType.slice(0, queryStart) : afterType;
  const query = new URLSearchParams(queryStart >= 0 ? afterType.slice(queryStart + 1).split('#', 1)[0] : '');

  const label = safeDecode(rawLabel).trim();
  let labelIssuer = '';
  let account = label;
  const colon = label.indexOf(':');
  if (colon >= 0) {
    labelIssuer = label.slice(0, colon).trim();
    account = label.slice(colon + 1).trim();
  }

  const counterParam = query.get('counter');
  if (typeRaw === 'hotp' && counterParam === null) {
    throw new Error('HOTP links must include a counter.');
  }

  const result = validateImported({
    type: typeRaw,
    issuer: (query.get('issuer') ?? labelIssuer).trim(),
    label: account,
    secret: query.get('secret') ?? '',
    algorithm: (query.get('algorithm') ?? DEFAULT_ALGORITHM) as AccountEntry['algorithm'],
    digits: Number(query.get('digits') ?? DEFAULT_DIGITS) as AccountEntry['digits'],
    period: Number(query.get('period') ?? DEFAULT_PERIOD),
    counter: Number(counterParam ?? 0),
  });
  if (typeof result === 'string') {
    throw new Error(result);
  }
  return result;
}

/** Serializes an account back into an otpauth:// URI for plaintext export. */
export function toOtpAuthUri(account: Pick<AccountEntry, 'type' | 'issuer' | 'label' | 'secret' | 'algorithm' | 'digits' | 'period' | 'counter'>): string {
  const label = account.issuer
    ? `${encodeURIComponent(account.issuer)}:${encodeURIComponent(account.label)}`
    : encodeURIComponent(account.label);
  const params = new URLSearchParams({ secret: account.secret });
  if (account.issuer) {
    params.set('issuer', account.issuer);
  }
  params.set('algorithm', ALGORITHM_PARAM[account.algorithm]);
  params.set('digits', String(account.digits));
  if (account.type === 'hotp') {
    params.set('counter', String(account.counter));
  } else {
    params.set('period', String(account.period));
  }
  return `${OTPAUTH_PREFIX}${account.type}/${label}?${params.toString().replace(/\+/g, '%20')}`;
}

/**
 * Pulls every otpauth:// URI out of free text. Handles one URI per line (where
 * an unencoded space or comma inside the label is tolerated) as well as comma,
 * semicolon or whitespace separated lists on a single line.
 */
export function extractOtpAuthUris(text: string): string[] {
  const out: string[] = [];
  for (const line of text.split(/\r?\n/)) {
    for (const part of line.split(/[\s,;]+(?=otpauth:\/\/)/i)) {
      const start = part.toLowerCase().indexOf(OTPAUTH_PREFIX);
      if (start < 0) {
        continue;
      }
      const uri = part.slice(start).trim().replace(/["'<>,;]+$/, '');
      if (uri.length > OTPAUTH_PREFIX.length) {
        out.push(uri);
      }
    }
  }
  return out;
}
