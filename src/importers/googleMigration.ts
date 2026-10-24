/**
 * Google Authenticator "Transfer accounts" export decoder.
 *
 * Export QR codes contain otpauth-migration://offline?data=BASE64, where the
 * payload is a Protocol Buffers encoded MigrationPayload:
 *
 *   message MigrationPayload {
 *     repeated OtpParameters otp_parameters = 1;
 *     int32 version = 2; int32 batch_size = 3; int32 batch_index = 4; int32 batch_id = 5;
 *   }
 *   message OtpParameters {
 *     bytes secret = 1; string name = 2; string issuer = 3;
 *     Algorithm algorithm = 4;  // 0 unspecified, 1 SHA1, 2 SHA256, 3 SHA512, 4 MD5
 *     DigitCount digits = 5;    // 0 unspecified, 1 six, 2 eight
 *     OtpType type = 6;         // 0 unspecified, 1 HOTP, 2 TOTP
 *     int64 counter = 7;
 *   }
 *
 * The wire-format reader below handles only what this schema needs, so no
 * protobuf runtime is bundled.
 */
import type { HashAlgorithm } from '../shared/types';
import { base64ToBytes, utf8Decode } from '../crypto/encoding';
import { base32Encode } from '../crypto/totp';
import { validateImported } from '../shared/accounts';
import { ImportCollector, type BatchInfo, type ImportResult } from './types';

const MIGRATION_PREFIX = 'otpauth-migration://';
const MAX_VARINT_BYTES = 10;

const WIRE_VARINT = 0;
const WIRE_FIXED64 = 1;
const WIRE_LENGTH_DELIMITED = 2;
const WIRE_FIXED32 = 5;

const ALGORITHMS: Readonly<Record<number, HashAlgorithm | 'MD5'>> = {
  0: 'SHA-1',
  1: 'SHA-1',
  2: 'SHA-256',
  3: 'SHA-512',
  4: 'MD5',
};

const DIGITS: Readonly<Record<number, 6 | 8>> = { 0: 6, 1: 6, 2: 8 };
const OTP_TYPES: Readonly<Record<number, 'totp' | 'hotp'>> = { 0: 'totp', 1: 'hotp', 2: 'totp' };

/** Minimal protobuf wire-format reader over a byte buffer. */
export class ProtoReader {
  private pos = 0;

  constructor(private readonly buf: Uint8Array) {}

  get done(): boolean {
    return this.pos >= this.buf.length;
  }

  readVarint(): bigint {
    let result = 0n;
    let shift = 0n;
    for (let i = 0; i < MAX_VARINT_BYTES; i += 1) {
      if (this.pos >= this.buf.length) {
        throw new Error('Truncated protobuf varint.');
      }
      const byte = this.buf[this.pos] as number;
      this.pos += 1;
      result |= BigInt(byte & 0x7f) << shift;
      if ((byte & 0x80) === 0) {
        return BigInt.asUintN(64, result);
      }
      shift += 7n;
    }
    throw new Error('Malformed protobuf varint.');
  }

  readTag(): { field: number; wireType: number } {
    const tag = Number(this.readVarint());
    return { field: tag >>> 3, wireType: tag & 0x07 };
  }

  readBytes(): Uint8Array {
    const length = Number(this.readVarint());
    if (this.pos + length > this.buf.length) {
      throw new Error('Truncated protobuf field.');
    }
    const out = this.buf.subarray(this.pos, this.pos + length);
    this.pos += length;
    return out;
  }

  readString(): string {
    return utf8Decode(this.readBytes());
  }

  private advance(count: number): void {
    if (this.pos + count > this.buf.length) {
      throw new Error('Truncated protobuf field.');
    }
    this.pos += count;
  }

  skip(wireType: number): void {
    switch (wireType) {
      case WIRE_VARINT:
        this.readVarint();
        return;
      case WIRE_FIXED64:
        this.advance(8);
        return;
      case WIRE_LENGTH_DELIMITED:
        this.readBytes();
        return;
      case WIRE_FIXED32:
        this.advance(4);
        return;
      default:
        throw new Error(`Unsupported protobuf wire type ${wireType}.`);
    }
  }
}

export interface MigrationOtp {
  secret: Uint8Array;
  name: string;
  issuer: string;
  algorithm: number;
  digits: number;
  type: number;
  counter: bigint;
}

export interface MigrationPayload {
  otpParameters: MigrationOtp[];
  version: number;
  batchSize: number;
  batchIndex: number;
  batchId: number;
}

function decodeOtpParameters(bytes: Uint8Array): MigrationOtp {
  const reader = new ProtoReader(bytes);
  const otp: MigrationOtp = {
    secret: new Uint8Array(0),
    name: '',
    issuer: '',
    algorithm: 0,
    digits: 0,
    type: 0,
    counter: 0n,
  };
  while (!reader.done) {
    const { field, wireType } = reader.readTag();
    if (field === 1 && wireType === WIRE_LENGTH_DELIMITED) {
      otp.secret = reader.readBytes().slice();
    } else if (field === 2 && wireType === WIRE_LENGTH_DELIMITED) {
      otp.name = reader.readString();
    } else if (field === 3 && wireType === WIRE_LENGTH_DELIMITED) {
      otp.issuer = reader.readString();
    } else if (field === 4 && wireType === WIRE_VARINT) {
      otp.algorithm = Number(reader.readVarint());
    } else if (field === 5 && wireType === WIRE_VARINT) {
      otp.digits = Number(reader.readVarint());
    } else if (field === 6 && wireType === WIRE_VARINT) {
      otp.type = Number(reader.readVarint());
    } else if (field === 7 && wireType === WIRE_VARINT) {
      otp.counter = reader.readVarint();
    } else {
      reader.skip(wireType);
    }
  }
  return otp;
}

/** Decodes the binary MigrationPayload message. */
export function decodeMigrationPayload(bytes: Uint8Array): MigrationPayload {
  const reader = new ProtoReader(bytes);
  const payload: MigrationPayload = { otpParameters: [], version: 0, batchSize: 1, batchIndex: 0, batchId: 0 };
  while (!reader.done) {
    const { field, wireType } = reader.readTag();
    if (field === 1 && wireType === WIRE_LENGTH_DELIMITED) {
      payload.otpParameters.push(decodeOtpParameters(reader.readBytes()));
    } else if (field >= 2 && field <= 5 && wireType === WIRE_VARINT) {
      // int32 fields are sign-extended to 64 bits on the wire.
      const value = Number(BigInt.asIntN(32, reader.readVarint()));
      if (field === 2) payload.version = value;
      else if (field === 3) payload.batchSize = value;
      else if (field === 4) payload.batchIndex = value;
      else payload.batchId = value;
    } else {
      reader.skip(wireType);
    }
  }
  return payload;
}

export function isGoogleMigrationUri(value: string): boolean {
  return value.trim().toLowerCase().startsWith(MIGRATION_PREFIX);
}

/** Finds every otpauth-migration:// URI in free text (one QR code per URI). */
export function extractMigrationUris(text: string): string[] {
  return text.match(/otpauth-migration:\/\/[^\s"'<>]+/gi) ?? [];
}

/**
 * Pulls the Base64 payload out of the URI. The value is percent-decoded by
 * hand because URLSearchParams would turn a literal "+" of the Base64 alphabet
 * into a space.
 */
export function migrationDataBytes(uri: string): Uint8Array {
  const trimmed = uri.trim();
  const query = trimmed.slice(trimmed.indexOf('?') + 1);
  const pair = query.split('&').find((p) => p.toLowerCase().startsWith('data='));
  if (!pair) {
    throw new Error('The Google Authenticator link has no data parameter.');
  }
  let value = pair.slice('data='.length);
  try {
    value = decodeURIComponent(value);
  } catch {
    throw new Error('The Google Authenticator link is not correctly URL-encoded.');
  }
  return base64ToBytes(value.replace(/ /g, '+'));
}

function splitName(name: string, issuer: string): { issuer: string; label: string } {
  const trimmedName = name.trim();
  const trimmedIssuer = issuer.trim();
  const colon = trimmedName.indexOf(':');
  if (colon < 0) {
    return { issuer: trimmedIssuer, label: trimmedName };
  }
  const prefix = trimmedName.slice(0, colon).trim();
  const rest = trimmedName.slice(colon + 1).trim();
  if (!trimmedIssuer) {
    return { issuer: prefix, label: rest };
  }
  if (prefix.toLowerCase() === trimmedIssuer.toLowerCase()) {
    return { issuer: trimmedIssuer, label: rest };
  }
  return { issuer: trimmedIssuer, label: trimmedName };
}

/** Parses one otpauth-migration:// URI into normalized accounts. */
export function parseGoogleMigrationUri(uri: string): ImportResult {
  if (!isGoogleMigrationUri(uri)) {
    throw new Error('Not a Google Authenticator export link.');
  }
  const payload = decodeMigrationPayload(migrationDataBytes(uri));
  const collector = new ImportCollector();
  payload.otpParameters.forEach((otp, index) => {
    const names = splitName(otp.name, otp.issuer);
    const context = names.issuer || names.label || `Entry ${index + 1}`;
    const algorithm = ALGORITHMS[otp.algorithm];
    if (!algorithm || algorithm === 'MD5') {
      collector.warn(`${context}: MD5 and unknown algorithms are not supported.`);
      return;
    }
    const digits = DIGITS[otp.digits];
    const type = OTP_TYPES[otp.type];
    if (!digits || !type) {
      collector.warn(`${context}: unsupported digit count or OTP type.`);
      return;
    }
    if (otp.counter > BigInt(Number.MAX_SAFE_INTEGER)) {
      collector.warn(`${context}: HOTP counter is too large.`);
      return;
    }
    collector.add(
      validateImported({
        type,
        issuer: names.issuer,
        label: names.label,
        secret: base32Encode(otp.secret),
        algorithm,
        digits,
        period: 30,
        counter: Number(otp.counter),
      }),
      context,
    );
  });
  const batch: BatchInfo = { id: payload.batchId, index: payload.batchIndex, size: Math.max(1, payload.batchSize) };
  return collector.finish('google-migration', batch);
}

/** Parses every migration URI found in a block of text and concatenates the results. */
export function parseGoogleMigrationText(text: string): ImportResult {
  const uris = extractMigrationUris(text);
  if (uris.length === 0) {
    throw new Error('No otpauth-migration:// links found.');
  }
  const collector = new ImportCollector();
  let batch: BatchInfo | undefined;
  for (const uri of uris) {
    const result = parseGoogleMigrationUri(uri);
    collector.accounts.push(...result.accounts);
    collector.warnings.push(...result.warnings);
    batch = uris.length === 1 ? result.batch : undefined;
  }
  return collector.finish('google-migration', batch);
}
