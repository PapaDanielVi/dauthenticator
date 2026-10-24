import { describe, expect, it } from 'vitest';
import {
  decodeMigrationPayload,
  isGoogleMigrationUri,
  parseGoogleMigrationText,
  parseGoogleMigrationUri,
} from '../../src/importers/googleMigration';
import { bytesToBase64 } from '../../src/crypto/encoding';

// Helper to assemble test protobuf messages
function encodeVarint(val: number | bigint): Uint8Array {
  let v = BigInt(val);
  const bytes: number[] = [];
  while (v >= 0x80n) {
    bytes.push(Number((v & 0x7fn) | 0x80n));
    v >>= 7n;
  }
  bytes.push(Number(v & 0x7fn));
  return new Uint8Array(bytes);
}

function encodeField(field: number, wireType: number, payload: Uint8Array): Uint8Array {
  const tag = (field << 3) | wireType;
  const tagBytes = encodeVarint(tag);
  const out = new Uint8Array(tagBytes.length + (wireType === 2 ? encodeVarint(payload.length).length : 0) + payload.length);
  out.set(tagBytes, 0);
  let offset = tagBytes.length;
  if (wireType === 2) {
    const lenBytes = encodeVarint(payload.length);
    out.set(lenBytes, offset);
    offset += lenBytes.length;
  }
  out.set(payload, offset);
  return out;
}

function concat(...bufs: Uint8Array[]): Uint8Array {
  const total = bufs.reduce((s, b) => s + b.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const b of bufs) {
    out.set(b, o);
    o += b.length;
  }
  return out;
}

describe('Google Authenticator Protobuf Importer', () => {
  it('detects migration URIs', () => {
    expect(isGoogleMigrationUri('otpauth-migration://offline?data=xyz')).toBe(true);
    expect(isGoogleMigrationUri('otpauth://totp/Test?secret=JBSWY3DPEHPK3PXP')).toBe(false);
  });

  it('decodes MigrationPayload protobuf wire format', () => {
    const secretBytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21]); // 6 bytes
    const nameBytes = new TextEncoder().encode('GitHub:danny');
    const issuerBytes = new TextEncoder().encode('GitHub');

    const otpParams = concat(
      encodeField(1, 2, secretBytes),
      encodeField(2, 2, nameBytes),
      encodeField(3, 2, issuerBytes),
      encodeField(4, 0, encodeVarint(1)), // SHA1
      encodeField(5, 0, encodeVarint(1)), // 6 digits
      encodeField(6, 0, encodeVarint(2)), // TOTP
      encodeField(7, 0, encodeVarint(0)), // counter
    );

    const payloadBytes = concat(
      encodeField(1, 2, otpParams),
      encodeField(2, 0, encodeVarint(1)), // version
      encodeField(3, 0, encodeVarint(1)), // batch_size
      encodeField(4, 0, encodeVarint(0)), // batch_index
      encodeField(5, 0, encodeVarint(9999)), // batch_id
    );

    const decoded = decodeMigrationPayload(payloadBytes);
    expect(decoded.version).toBe(1);
    expect(decoded.batchSize).toBe(1);
    expect(decoded.batchId).toBe(9999);
    expect(decoded.otpParameters.length).toBe(1);

    const item = decoded.otpParameters[0];
    expect(item?.issuer).toBe('GitHub');
    expect(item?.name).toBe('GitHub:danny');
    expect(item?.algorithm).toBe(1);
    expect(item?.digits).toBe(1);
    expect(item?.type).toBe(2);
  });

  it('parses real Google migration URI with percent-encoded data', () => {
    const secretBytes = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21]);
    const otpParams = concat(
      encodeField(1, 2, secretBytes),
      encodeField(2, 2, new TextEncoder().encode('Proton:user@proton.me')),
      encodeField(3, 2, new TextEncoder().encode('Proton')),
      encodeField(4, 0, encodeVarint(1)), // SHA1
      encodeField(5, 0, encodeVarint(1)), // 6 digits
      encodeField(6, 0, encodeVarint(2)), // TOTP
    );

    const payloadBytes = concat(
      encodeField(1, 2, otpParams),
      encodeField(2, 0, encodeVarint(1)),
      encodeField(3, 0, encodeVarint(1)),
      encodeField(4, 0, encodeVarint(0)),
      encodeField(5, 0, encodeVarint(101)),
    );

    const b64 = bytesToBase64(payloadBytes);
    const uri = `otpauth-migration://offline?data=${encodeURIComponent(b64)}`;

    const result = parseGoogleMigrationUri(uri);
    expect(result.source).toBe('google-migration');
    expect(result.accounts.length).toBe(1);

    const acc = result.accounts[0];
    expect(acc?.issuer).toBe('Proton');
    expect(acc?.label).toBe('user@proton.me');
    expect(acc?.algorithm).toBe('SHA-1');
    expect(acc?.digits).toBe(6);
    expect(acc?.period).toBe(30);
    expect(acc?.type).toBe('totp');
    expect(result.batch?.size).toBe(1);
  });

  it('handles batch migration links in a single text', () => {
    const otp1 = concat(
      encodeField(1, 2, new Uint8Array([1, 2, 3, 4, 5])),
      encodeField(2, 2, new TextEncoder().encode('AWS:admin')),
      encodeField(3, 2, new TextEncoder().encode('AWS')),
      encodeField(4, 0, encodeVarint(1)),
      encodeField(5, 0, encodeVarint(1)),
      encodeField(6, 0, encodeVarint(2)),
    );
    const payload1 = concat(encodeField(1, 2, otp1), encodeField(2, 0, encodeVarint(1)));
    const uri1 = `otpauth-migration://offline?data=${encodeURIComponent(bytesToBase64(payload1))}`;

    const text = `Here is my export:\n${uri1}\nCheck it out!`;
    const res = parseGoogleMigrationText(text);
    expect(res.accounts.length).toBe(1);
    expect(res.accounts[0]?.issuer).toBe('AWS');
  });
});
