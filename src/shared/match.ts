/**
 * Matching of the active tab's hostname against saved accounts, used to pick
 * the right code for autofill and to surface suggestions in the popup.
 */
import type { AccountEntry } from './types';

/** Words that carry no signal when comparing issuers with hostnames. */
const STOP_WORDS = new Set([
  'the', 'inc', 'llc', 'ltd', 'corp', 'com', 'net', 'org', 'www', 'app', 'login', 'account', 'accounts',
  'auth', 'online', 'web', 'services', 'service', 'cloud', 'mail', 'secure', 'portal',
]);

const MIN_TOKEN_LENGTH = 3;

export const SCORE_EXPLICIT_DOMAIN = 100;
export const SCORE_ISSUER_DOMAIN = 90;
export const SCORE_ISSUER_COMPACT = 60;
export const SCORE_ISSUER_TOKEN = 40;

/**
 * Turns "https://www.GitHub.com/login" or "github.com." into "github.com".
 * Returns null for things that do not look like hostnames.
 */
export function normalizeDomain(input: string): string | null {
  let value = input.trim().toLowerCase();
  if (!value) {
    return null;
  }
  value = value.replace(/^[a-z][a-z0-9+.-]*:\/\//, '');
  value = value.split(/[/?#]/, 1)[0] ?? '';
  value = value.replace(/^[^@]*@/, '').replace(/:\d+$/, '').replace(/\.$/, '').replace(/^www\./, '');
  if (!/^[a-z0-9.-]+$/.test(value) || !value.includes('.') || value.startsWith('.') || value.includes('..')) {
    return null;
  }
  return value;
}

/** Hostname of an http(s) URL, or null for chrome://, file:// and friends. */
export function hostnameFromUrl(url: string | undefined): string | null {
  if (!url) {
    return null;
  }
  try {
    const parsed = new URL(url);
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
      return null;
    }
    return normalizeDomain(parsed.hostname) ?? parsed.hostname.toLowerCase();
  } catch {
    return null;
  }
}

function domainMatches(hostname: string, domain: string): boolean {
  return hostname === domain || hostname.endsWith(`.${domain}`);
}

function tokens(text: string): string[] {
  return text
    .toLowerCase()
    .split(/[^a-z0-9]+/)
    .filter((t) => t.length >= MIN_TOKEN_LENGTH && !STOP_WORDS.has(t));
}

/** Scores how likely an account belongs to a hostname. 0 means no match. */
export function scoreAccount(account: Pick<AccountEntry, 'issuer' | 'domains'>, hostname: string): number {
  const host = normalizeDomain(hostname) ?? hostname.toLowerCase();
  if (account.domains.some((d) => domainMatches(host, d))) {
    return SCORE_EXPLICIT_DOMAIN;
  }
  const issuer = account.issuer.trim().toLowerCase();
  if (!issuer) {
    return 0;
  }
  const issuerDomain = normalizeDomain(issuer);
  if (issuerDomain && domainMatches(host, issuerDomain)) {
    return SCORE_ISSUER_DOMAIN;
  }
  const labels = host.split('.');
  const compact = issuer.replace(/[^a-z0-9]/g, '');
  if (compact.length >= MIN_TOKEN_LENGTH && labels.includes(compact)) {
    return SCORE_ISSUER_COMPACT;
  }
  if (tokens(issuer).some((t) => labels.includes(t))) {
    return SCORE_ISSUER_TOKEN;
  }
  return 0;
}

export interface AccountMatch {
  account: AccountEntry;
  score: number;
}

/** All accounts that match the hostname, best first. */
export function matchAccounts(accounts: readonly AccountEntry[], hostname: string | null): AccountMatch[] {
  if (!hostname) {
    return [];
  }
  return accounts
    .map((account) => ({ account, score: scoreAccount(account, hostname) }))
    .filter((m) => m.score > 0)
    .sort((a, b) => b.score - a.score);
}

/**
 * The single account to autofill, or null when there is no match or the top
 * score is shared by several accounts and the user has to choose.
 */
export function pickAutofillAccount(matches: readonly AccountMatch[]): AccountEntry | null {
  const [first, second] = matches;
  if (!first) {
    return null;
  }
  if (second && second.score === first.score) {
    return null;
  }
  return first.account;
}
