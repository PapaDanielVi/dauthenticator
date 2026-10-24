import { describe, expect, it } from 'vitest';
import { importFromText } from '../../src/importers/fileImporters';
import { parseOtpAuthUri, toOtpAuthUri } from '../../src/importers/otpauthUri';
import { PasswordRequiredError } from '../../src/shared/errors';
import { bytesToBase64, hexToBytes, utf8Encode } from '../../src/crypto/encoding';
import { scryptAsync } from '@noble/hashes/scrypt.js';

describe('File & Format Importers', () => {
  it('parses standard otpauth:// URIs and serializes them back', () => {
    const uri = 'otpauth://totp/GitHub:danny?secret=JBSWY3DPEHPK3PXP&issuer=GitHub&algorithm=SHA256&digits=8&period=60';
    const parsed = parseOtpAuthUri(uri);

    expect(parsed.issuer).toBe('GitHub');
    expect(parsed.label).toBe('danny');
    expect(parsed.secret).toBe('JBSWY3DPEHPK3PXP');
    expect(parsed.algorithm).toBe('SHA-256');
    expect(parsed.digits).toBe(8);
    expect(parsed.period).toBe(60);
    expect(parsed.type).toBe('totp');

    const serialized = toOtpAuthUri(parsed);
    expect(serialized).toContain('otpauth://totp/GitHub:danny?');
    expect(serialized).toContain('secret=JBSWY3DPEHPK3PXP');
    expect(serialized).toContain('digits=8');
  });

  it('parses multiple newline-separated otpauth:// URIs', async () => {
    const text = `
      otpauth://totp/Google:user1@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Google
      otpauth://hotp/Dropbox:user2?secret=JBSWY3DPEHPK3PXP&issuer=Dropbox&counter=42
    `;
    const res = await importFromText(text);
    expect(res.source).toBe('otpauth');
    expect(res.accounts.length).toBe(2);
    expect(res.accounts[0]?.issuer).toBe('Google');
    expect(res.accounts[1]?.type).toBe('hotp');
    expect(res.accounts[1]?.counter).toBe(42);
  });

  it('parses 2FAS unencrypted JSON exports', async () => {
    const data = {
      services: [
        {
          name: 'Cloudflare',
          secret: 'JBSWY3DPEHPK3PXP',
          otp: {
            issuer: 'Cloudflare',
            account: 'admin@company.com',
            tokenType: 'TOTP',
            digits: 6,
            period: 30,
            algorithm: 'SHA1',
          },
        },
      ],
    };
    const res = await importFromText(JSON.stringify(data));
    expect(res.source).toBe('2fas');
    expect(res.accounts.length).toBe(1);
    expect(res.accounts[0]?.issuer).toBe('Cloudflare');
    expect(res.accounts[0]?.label).toBe('admin@company.com');
  });

  it('parses Aegis unencrypted JSON exports', async () => {
    const data = {
      version: 1,
      header: { slots: null, params: null },
      db: {
        version: 1,
        entries: [
          {
            type: 'totp',
            name: 'john_doe',
            issuer: 'DigitalOcean',
            info: {
              secret: 'JBSWY3DPEHPK3PXP',
              algo: 'SHA1',
              digits: 6,
              period: 30,
            },
          },
        ],
      },
    };
    const res = await importFromText(JSON.stringify(data));
    expect(res.source).toBe('aegis');
    expect(res.accounts.length).toBe(1);
    expect(res.accounts[0]?.issuer).toBe('DigitalOcean');
    expect(res.accounts[0]?.label).toBe('john_doe');
  });

  it('decrypts password-protected Aegis exports using scrypt + AES-GCM', async () => {
    const password = 'aegis-test-password';
    const saltHex = '0102030405060708090a0b0c0d0e0f10';
    const n = 16384;
    const r = 8;
    const p = 1;

    // Derive test master key
    const derived = new Uint8Array(await scryptAsync(utf8Encode(password), hexToBytes(saltHex), { N: n, r, p, dkLen: 32 }));
    const masterKeyBytes = new Uint8Array(32);
    crypto.getRandomValues(masterKeyBytes);

    // Encrypt master key in slot
    const slotIv = new Uint8Array(12);
    crypto.getRandomValues(slotIv);
    const slotKey = await crypto.subtle.importKey('raw', derived, 'AES-GCM', false, ['encrypt']);
    const slotCipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: slotIv, tagLength: 128 }, slotKey, masterKeyBytes));
    const slotEncryptedKey = slotCipher.slice(0, slotCipher.length - 16);
    const slotTag = slotCipher.slice(slotCipher.length - 16);

    // Encrypt db payload
    const dbPayload = {
      version: 1,
      entries: [
        {
          type: 'totp',
          name: 'alice',
          issuer: 'Stripe',
          info: { secret: 'JBSWY3DPEHPK3PXP', algo: 'SHA256', digits: 6, period: 30 },
        },
      ],
    };
    const dbIv = new Uint8Array(12);
    crypto.getRandomValues(dbIv);
    const dbKey = await crypto.subtle.importKey('raw', masterKeyBytes, 'AES-GCM', false, ['encrypt']);
    const dbCipher = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: dbIv, tagLength: 128 }, dbKey, utf8Encode(JSON.stringify(dbPayload))));
    const dbEncrypted = dbCipher.slice(0, dbCipher.length - 16);
    const dbTag = dbCipher.slice(dbCipher.length - 16);

    const toHex = (b: Uint8Array) => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

    const aegisData = {
      version: 1,
      header: {
        slots: [
          {
            type: 1,
            key: toHex(slotEncryptedKey),
            key_params: { nonce: toHex(slotIv), tag: toHex(slotTag) },
            n,
            r,
            p,
            salt: saltHex,
          },
        ],
        params: { nonce: toHex(dbIv), tag: toHex(dbTag) },
      },
      db: bytesToBase64(dbEncrypted),
    };

    // Attempt without password throws PasswordRequiredError
    await expect(importFromText(JSON.stringify(aegisData))).rejects.toThrow(PasswordRequiredError);

    // Attempt with correct password succeeds
    const res = await importFromText(JSON.stringify(aegisData), { password });
    expect(res.source).toBe('aegis');
    expect(res.accounts.length).toBe(1);
    expect(res.accounts[0]?.issuer).toBe('Stripe');
    expect(res.accounts[0]?.algorithm).toBe('SHA-256');
  });

  it('parses Bitwarden unencrypted JSON exports', async () => {
    const data = {
      encrypted: false,
      items: [
        {
          name: 'Amazon Web Services',
          login: {
            username: 'dev@company.com',
            totp: 'otpauth://totp/Amazon%20Web%20Services:dev@company.com?secret=JBSWY3DPEHPK3PXP',
            uris: [{ uri: 'https://signin.aws.amazon.com/console' }],
          },
        },
      ],
    };
    const res = await importFromText(JSON.stringify(data));
    expect(res.source).toBe('bitwarden-json');
    expect(res.accounts.length).toBe(1);
    expect(res.accounts[0]?.issuer).toBe('Amazon Web Services');
    expect(res.accounts[0]?.domains).toEqual(['signin.aws.amazon.com']);
  });

  it('parses Bitwarden CSV exports', async () => {
    const csv = `folder,favorite,type,name,notes,fields,reprompt,login_uri,login_username,login_password,login_totp
,0,login,Slack,,,0,https://slack.com,slackuser@work.com,,JBSWY3DPEHPK3PXP`;

    const res = await importFromText(csv);
    expect(res.source).toBe('bitwarden-csv');
    expect(res.accounts.length).toBe(1);
    expect(res.accounts[0]?.issuer).toBe('Slack');
    expect(res.accounts[0]?.label).toBe('slackuser@work.com');
    expect(res.accounts[0]?.domains).toEqual(['slack.com']);
  });

  it('parses generic JSON exports via heuristic mapper', async () => {
    const genericJson = [
      {
        provider: 'GitLab',
        email: 'dev@gitlab.com',
        seed: 'JBSWY3DPEHPK3PXP',
        digits: 6,
        step: 30,
        website: 'https://gitlab.com/users/sign_in',
      },
    ];
    const res = await importFromText(JSON.stringify(genericJson));
    expect(res.source).toBe('generic-json');
    expect(res.accounts.length).toBe(1);
    expect(res.accounts[0]?.issuer).toBe('GitLab');
    expect(res.accounts[0]?.label).toBe('dev@gitlab.com');
    expect(res.accounts[0]?.domains).toEqual(['gitlab.com']);
  });

  it('parses generic CSV exports via heuristic mapper', async () => {
    const genericCsv = `Issuer;Account;Secret;Algorithm;Digits
Reddit;reddit_user;JBSWY3DPEHPK3PXP;SHA1;6`;

    const res = await importFromText(genericCsv);
    expect(res.source).toBe('generic-csv');
    expect(res.accounts.length).toBe(1);
    expect(res.accounts[0]?.issuer).toBe('Reddit');
    expect(res.accounts[0]?.label).toBe('reddit_user');
  });
});
