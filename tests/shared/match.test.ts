import { describe, expect, it } from 'vitest';
import {
  hostnameFromUrl,
  matchAccounts,
  normalizeDomain,
  pickAutofillAccount,
  scoreAccount,
} from '../../src/shared/match';
import type { AccountEntry } from '../../src/shared/types';

function makeAccount(issuer: string, label: string, domains: string[] = []): AccountEntry {
  return {
    id: `acc-${issuer}`,
    type: 'totp',
    issuer,
    label,
    secret: 'JBSWY3DPEHPK3PXP',
    algorithm: 'SHA-1',
    digits: 6,
    period: 30,
    counter: 0,
    domains,
    createdAt: 0,
    updatedAt: 0,
  };
}

describe('Domain & Autofill Matching', () => {
  it('normalizes URLs and hostnames', () => {
    expect(normalizeDomain('https://www.github.com/login')).toBe('github.com');
    expect(normalizeDomain('login.live.com:443')).toBe('login.live.com');
    expect(normalizeDomain('https://AWS.Amazon.com/')).toBe('aws.amazon.com');
    expect(normalizeDomain('not-a-domain')).toBe(null);
  });

  it('extracts hostname from full URLs', () => {
    expect(hostnameFromUrl('https://accounts.google.com/signin/v2')).toBe('accounts.google.com');
    expect(hostnameFromUrl('chrome://extensions')).toBe(null);
    expect(hostnameFromUrl('file:///home/user/doc.html')).toBe(null);
  });

  it('scores explicit domain matches highest', () => {
    const acc = makeAccount('Work Cloud', 'user@work.com', ['portal.work.com']);
    expect(scoreAccount(acc, 'portal.work.com')).toBe(100);
    // Subdomain of matched domain
    expect(scoreAccount(acc, 'auth.portal.work.com')).toBe(100);
  });

  it('scores issuer domain matches', () => {
    const acc = makeAccount('gitlab.com', 'danny');
    expect(scoreAccount(acc, 'gitlab.com')).toBe(90);
    expect(scoreAccount(acc, 'about.gitlab.com')).toBe(90);
  });

  it('scores issuer tokens matching host labels', () => {
    const acc = makeAccount('GitHub', 'danny');
    expect(scoreAccount(acc, 'github.com')).toBe(60);
    expect(scoreAccount(acc, 'gist.github.com')).toBe(60);
    expect(scoreAccount(acc, 'randomsite.org')).toBe(0);
  });

  it('picks single best candidate or returns null on tie', () => {
    const acc1 = makeAccount('GitHub', 'work-user', ['github.com']);
    const acc2 = makeAccount('GitHub Personal', 'home-user', ['github.com']);
    const acc3 = makeAccount('Slack', 'work-user', ['slack.com']);

    const matches = matchAccounts([acc1, acc2, acc3], 'github.com');
    expect(matches.length).toBe(2);

    // Two accounts tied with score 100 on github.com -> pickAutofillAccount returns null so user chooses
    expect(pickAutofillAccount(matches)).toBe(null);

    // Single match on slack.com -> returns acc3
    const slackMatches = matchAccounts([acc1, acc2, acc3], 'slack.com');
    expect(slackMatches.length).toBe(1);
    expect(pickAutofillAccount(slackMatches)?.id).toBe('acc-Slack');
  });
});
