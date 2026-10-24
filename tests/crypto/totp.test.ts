import { describe, expect, it } from 'vitest';
import {
  base32Decode,
  base32Encode,
  formatCode,
  generateHotp,
  generateTotp,
  isValidBase32,
  normalizeBase32,
  parseAlgorithm,
  secondsRemaining,
  timeStep,
} from '../../src/crypto/totp';

describe('Base32 Codec', () => {
  it('encodes and decodes standard byte arrays', () => {
    const input = new TextEncoder().encode('Hello 2FA World!');
    const encoded = base32Encode(input);
    const decoded = base32Decode(encoded);
    expect(new TextDecoder().decode(decoded)).toBe('Hello 2FA World!');
  });

  it('normalizes spaces, dashes, and lowercase characters', () => {
    const raw = 'jbsw-y3dp-ehpk-3pxp';
    expect(normalizeBase32(raw)).toBe('JBSWY3DPEHPK3PXP');
    expect(isValidBase32(raw)).toBe(true);
    expect(base32Decode(raw).length).toBe(10);
  });

  it('detects invalid Base32 strings', () => {
    expect(isValidBase32('')).toBe(false);
    expect(isValidBase32('1890')).toBe(false); // 1, 8, 9, 0 are not in RFC 4648 Base32
    expect(isValidBase32('A')).toBe(false); // Too short to encode whole bytes
  });
});

describe('RFC 4226 HOTP Vectors', () => {
  // RFC 4226 Section 12 test vectors with secret "12345678901234567890" (ASCII)
  const secret = new TextEncoder().encode('12345678901234567890');
  const expectedCodes = [
    '755224', // count 0
    '287082', // count 1
    '359152', // count 2
    '969429', // count 3
    '338314', // count 4
    '254676', // count 5
    '287922', // count 6
    '162583', // count 7
    '399871', // count 8
    '520489', // count 9
  ];

  it('generates exact RFC 4226 codes for counts 0 through 9', async () => {
    for (let counter = 0; counter < expectedCodes.length; counter++) {
      const code = await generateHotp({ secret, algorithm: 'SHA-1', digits: 6 }, counter);
      expect(code).toBe(expectedCodes[counter]);
    }
  });
});

describe('RFC 6238 TOTP Vectors', () => {
  // RFC 6238 Appendix B test vectors
  const secretSha1 = new TextEncoder().encode('12345678901234567890'); // 20 bytes
  const secretSha256 = new TextEncoder().encode('12345678901234567890123456789012'); // 32 bytes
  const secretSha512 = new TextEncoder().encode('1234567890123456789012345678901234567890123456789012345678901234'); // 64 bytes

  it('matches RFC 6238 SHA-1 (8 digits)', async () => {
    // T = 59s -> 94287082
    expect(await generateTotp({ secret: secretSha1, algorithm: 'SHA-1', digits: 8, period: 30 }, 59 * 1000)).toBe('94287082');
    // T = 1111111109s -> 07081804
    expect(await generateTotp({ secret: secretSha1, algorithm: 'SHA-1', digits: 8, period: 30 }, 1111111109 * 1000)).toBe('07081804');
    // T = 1234567890s -> 89005924
    expect(await generateTotp({ secret: secretSha1, algorithm: 'SHA-1', digits: 8, period: 30 }, 1234567890 * 1000)).toBe('89005924');
    // T = 2000000000s -> 69279037
    expect(await generateTotp({ secret: secretSha1, algorithm: 'SHA-1', digits: 8, period: 30 }, 2000000000 * 1000)).toBe('69279037');
  });

  it('matches RFC 6238 SHA-256 (8 digits)', async () => {
    // T = 59s -> 46119246
    expect(await generateTotp({ secret: secretSha256, algorithm: 'SHA-256', digits: 8, period: 30 }, 59 * 1000)).toBe('46119246');
    // T = 1111111109s -> 68084774
    expect(await generateTotp({ secret: secretSha256, algorithm: 'SHA-256', digits: 8, period: 30 }, 1111111109 * 1000)).toBe('68084774');
    // T = 1234567890s -> 91819424
    expect(await generateTotp({ secret: secretSha256, algorithm: 'SHA-256', digits: 8, period: 30 }, 1234567890 * 1000)).toBe('91819424');
  });

  it('matches RFC 6238 SHA-512 (8 digits)', async () => {
    // T = 59s -> 90693936
    expect(await generateTotp({ secret: secretSha512, algorithm: 'SHA-512', digits: 8, period: 30 }, 59 * 1000)).toBe('90693936');
    // T = 1111111109s -> 25091201
    expect(await generateTotp({ secret: secretSha512, algorithm: 'SHA-512', digits: 8, period: 30 }, 1111111109 * 1000)).toBe('25091201');
    // T = 1234567890s -> 93441116
    expect(await generateTotp({ secret: secretSha512, algorithm: 'SHA-512', digits: 8, period: 30 }, 1234567890 * 1000)).toBe('93441116');
  });

  it('calculates remaining seconds and time steps accurately', () => {
    const period = 30;
    // Exactly at second 10 of a 30s period -> 20s left
    const now = 10 * 1000;
    expect(secondsRemaining(period, now)).toBe(20);
    expect(timeStep(period, now)).toBe(0);
    // At second 29.5 -> 0.5s left
    expect(secondsRemaining(period, 29500)).toBe(0.5);
    expect(timeStep(period, 65 * 1000)).toBe(2);
  });

  it('formats codes with clean spacing', () => {
    expect(formatCode('123456')).toBe('123 456');
    expect(formatCode('12345678')).toBe('1234 5678');
    expect(formatCode('1234567')).toBe('1234567');
  });

  it('parses algorithm variants correctly', () => {
    expect(parseAlgorithm('sha1')).toBe('SHA-1');
    expect(parseAlgorithm('HMAC-SHA256')).toBe('SHA-256');
    expect(parseAlgorithm('SHA512')).toBe('SHA-512');
    expect(parseAlgorithm('md5')).toBe(null);
  });
});
