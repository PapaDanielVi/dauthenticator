/**
 * Unified import dispatcher for text based exports. Detects the format of a
 * pasted string or uploaded file and normalizes every entry into an
 * ImportedAccount.
 *
 * Supported formats:
 *   - otpauth:// lists (.txt / .uri from Ente Auth, Raivo, plaintext)
 *   - Google Authenticator otpauth-migration:// links
 *   - 2FAS (.2fas / .json), plain or password protected
 *   - Aegis (.json), plain or password protected
 *   - Bitwarden vault and Bitwarden Authenticator exports (.json / .csv)
 *   - DAuthenticator backups (.dauth.enc / .json)
 *   - Anything else that is an unencrypted JSON or CSV export with familiar keys
 */
import type { AccountEntry, ImportedAccount } from '../shared/types';
import { sanitizeAccount, validateImported } from '../shared/accounts';
import { normalizeDomain } from '../shared/match';
import { PasswordRequiredError } from '../shared/errors';
import { decryptWithPassword, decryptWithSession, isEncryptedVault, WrongPasswordError, type EncryptedVault } from '../crypto/vault';
import { isValidBase32, normalizeBase32 } from '../crypto/totp';
import { extractOtpAuthUris, isOtpAuthUri, parseOtpAuthUri } from './otpauthUri';
import { extractMigrationUris, parseGoogleMigrationUri } from './googleMigration';
import { decrypt2fasServices, decryptAegis, isAegisFile } from './encryptedBackups';
import { csvHeaderLooksUsable, importGenericCsvRecords, importGenericJson } from './heuristic';
import { detectDelimiter, parseCsv, parseCsvObjects } from './csv';
import { ImportCollector, type ImportOptions, type ImportResult } from './types';

export const DAUTH_APP_ID = 'DAuthenticator';
export const DAUTH_ENCRYPTED_KIND = 'encrypted-backup';
export const DAUTH_PLAIN_KIND = 'plain-backup';

/** Shape of DAuthenticator's own export files. */
export interface DAuthBackupFile {
  app: typeof DAUTH_APP_ID;
  kind: typeof DAUTH_ENCRYPTED_KIND | typeof DAUTH_PLAIN_KIND;
  exportedAt: string;
  vault?: EncryptedVault;
  accounts?: unknown[];
}

function messageOf(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

function asRecord(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value) ? (value as Record<string, unknown>) : {};
}

function str(value: unknown): string {
  return typeof value === 'string' ? value.trim() : typeof value === 'number' ? String(value) : '';
}

function num(value: unknown): number | undefined {
  if (value === undefined || value === null || value === '') {
    return undefined;
  }
  const n = Number(value);
  return Number.isFinite(n) ? n : Number.NaN;
}

/** Parses a list of otpauth:// URIs (newline, comma or whitespace separated). */
export function importOtpAuthList(text: string): ImportResult {
  const collector = new ImportCollector();
  extractOtpAuthUris(text).forEach((uri, index) => {
    try {
      collector.add(parseOtpAuthUri(uri), `Line ${index + 1}`);
    } catch (error) {
      collector.warn(`Line ${index + 1}: ${messageOf(error)}`);
    }
  });
  return collector.finish('otpauth');
}

/** Parses one or more Google Authenticator export links, plus any loose otpauth:// links. */
export function importGoogleMigration(text: string): ImportResult {
  const collector = new ImportCollector();
  const uris = extractMigrationUris(text);
  let batch: ImportResult['batch'];
  for (const uri of uris) {
    try {
      const result = parseGoogleMigrationUri(uri);
      collector.accounts.push(...result.accounts);
      collector.warnings.push(...result.warnings);
      batch = uris.length === 1 ? result.batch : undefined;
    } catch (error) {
      collector.warn(`Google Authenticator export: ${messageOf(error)}`);
    }
  }
  const loose = importOtpAuthList(text);
  collector.accounts.push(...loose.accounts);
  collector.warnings.push(...loose.warnings);
  return collector.finish('google-migration', batch);
}

/** Maps a 2FAS service object. */
function map2fasService(service: unknown): ImportedAccount | string {
  const s = asRecord(service);
  const otp = asRecord(s.otp);
  const tokenType = str(otp.tokenType).toUpperCase() || 'TOTP';
  if (tokenType !== 'TOTP' && tokenType !== 'HOTP') {
    return `${tokenType} tokens are not supported.`;
  }
  const link = str(otp.link);
  if (link && isOtpAuthUri(link)) {
    try {
      const parsed = parseOtpAuthUri(link);
      return { ...parsed, issuer: parsed.issuer || str(otp.issuer) || str(s.name) };
    } catch {
      // Fall through to the structured fields below.
    }
  }
  return validateImported({
    type: tokenType === 'HOTP' ? 'hotp' : 'totp',
    issuer: str(otp.issuer) || str(s.name),
    label: str(otp.account) || str(otp.label) || str(s.account),
    secret: str(s.secret) || str(otp.secret),
    algorithm: (str(otp.algorithm) || undefined) as ImportedAccount['algorithm'] | undefined,
    digits: num(otp.digits) as ImportedAccount['digits'] | undefined,
    period: num(otp.period),
    counter: num(otp.counter),
  });
}

/** 2FAS Authenticator backup (.2fas). */
export async function import2fas(json: Record<string, unknown>, options: ImportOptions): Promise<ImportResult> {
  let services: unknown[] = Array.isArray(json.services) ? json.services : [];
  if (services.length === 0 && typeof json.servicesEncrypted === 'string' && json.servicesEncrypted) {
    services = await decrypt2fasServices(json.servicesEncrypted, options.password);
  }
  const collector = new ImportCollector();
  services.forEach((service, index) => {
    collector.add(map2fasService(service), str(asRecord(service).name) || `Service ${index + 1}`);
  });
  return collector.finish('2fas');
}

/** Maps an Aegis database entry. */
function mapAegisEntry(entry: unknown): ImportedAccount | string {
  const e = asRecord(entry);
  const info = asRecord(e.info);
  const type = str(e.type).toLowerCase();
  if (type !== 'totp' && type !== 'hotp') {
    return `${type || 'unknown'} entries are not supported.`;
  }
  let issuer = str(e.issuer);
  let label = str(e.name);
  if (!issuer && label.includes(':')) {
    const colon = label.indexOf(':');
    issuer = label.slice(0, colon).trim();
    label = label.slice(colon + 1).trim();
  }
  return validateImported({
    type,
    issuer,
    label,
    secret: str(info.secret),
    algorithm: (str(info.algo) || undefined) as ImportedAccount['algorithm'] | undefined,
    digits: num(info.digits) as ImportedAccount['digits'] | undefined,
    period: num(info.period),
    counter: num(info.counter),
  });
}

/** Aegis Authenticator export, plain or encrypted. */
export async function importAegis(json: unknown, options: ImportOptions): Promise<ImportResult> {
  if (!isAegisFile(json)) {
    throw new Error('Not an Aegis backup.');
  }
  const db = asRecord(await decryptAegis(json, options.password));
  const entries = Array.isArray(db.entries) ? db.entries : [];
  const collector = new ImportCollector();
  entries.forEach((entry, index) => {
    const e = asRecord(entry);
    collector.add(mapAegisEntry(entry), str(e.issuer) || str(e.name) || `Entry ${index + 1}`);
  });
  return collector.finish('aegis');
}

/** Maps a Bitwarden login (from JSON or CSV) onto an account. */
function mapBitwardenLogin(totp: string, name: string, username: string, uris: string[]): ImportedAccount | string | null {
  if (!totp) {
    return null;
  }
  if (/^steam:\/\//i.test(totp)) {
    return 'Steam Guard codes are not supported.';
  }
  const domains = uris.map((u) => normalizeDomain(u)).filter((d): d is string => d !== null);
  if (isOtpAuthUri(totp)) {
    try {
      const parsed = parseOtpAuthUri(totp);
      return {
        ...parsed,
        issuer: parsed.issuer || name,
        label: parsed.label || username,
        domains,
      };
    } catch (error) {
      return messageOf(error);
    }
  }
  return validateImported({ type: 'totp', issuer: name, label: username, secret: totp, domains });
}

/** Bitwarden password manager or Bitwarden Authenticator JSON export. */
export function importBitwardenJson(json: Record<string, unknown>): ImportResult {
  if (json.encrypted === true) {
    throw new Error('This Bitwarden export is encrypted. Export again using the unencrypted ".json" format.');
  }
  const items = Array.isArray(json.items) ? json.items : [];
  const collector = new ImportCollector();
  items.forEach((item, index) => {
    const i = asRecord(item);
    const login = asRecord(i.login);
    const uris = (Array.isArray(login.uris) ? login.uris : []).map((u) => str(asRecord(u).uri)).filter(Boolean);
    const name = str(i.name);
    const mapped = mapBitwardenLogin(str(login.totp), name, str(login.username), uris);
    if (mapped !== null) {
      collector.add(mapped, name || `Item ${index + 1}`);
    }
  });
  return collector.finish('bitwarden-json');
}

/** Bitwarden CSV export (columns name, login_uri, login_username, login_totp). */
export function importBitwardenCsv(records: readonly Record<string, string>[]): ImportResult {
  const collector = new ImportCollector();
  records.forEach((record, index) => {
    const uris = (record.login_uri ?? '').split(/[,\n]/).map((u) => u.trim()).filter(Boolean);
    const name = record.name ?? '';
    const mapped = mapBitwardenLogin(record.login_totp ?? '', name, record.login_username ?? '', uris);
    if (mapped !== null) {
      collector.add(mapped, name || `Row ${index + 2}`);
    }
  });
  return collector.finish('bitwarden-csv');
}

function isDAuthBackup(value: unknown): value is DAuthBackupFile {
  return asRecord(value).app === DAUTH_APP_ID;
}

/** DAuthenticator encrypted or plaintext backup. */
export async function importDAuthBackup(file: DAuthBackupFile | EncryptedVault, options: ImportOptions): Promise<ImportResult> {
  let accounts: unknown[] = [];
  const envelope = isEncryptedVault(file) ? file : file.vault;
  if (envelope && isEncryptedVault(envelope)) {
    let data = await decryptWithSession<{ accounts?: unknown[] }>(envelope).catch(() => null);
    if (!data) {
      if (!options.password) {
        throw new PasswordRequiredError('dauthenticator');
      }
      try {
        data = await decryptWithPassword<{ accounts?: unknown[] }>(envelope, options.password);
      } catch (error) {
        if (error instanceof WrongPasswordError) {
          throw new PasswordRequiredError('dauthenticator', true);
        }
        throw error;
      }
    }
    accounts = Array.isArray(data.accounts) ? data.accounts : [];
  } else if ('accounts' in file && Array.isArray(file.accounts)) {
    accounts = file.accounts;
  } else {
    throw new Error('The DAuthenticator backup is missing its data.');
  }
  const collector = new ImportCollector();
  accounts.forEach((raw, index) => {
    const account: AccountEntry | null = sanitizeAccount(raw);
    if (account) {
      collector.accounts.push({
        type: account.type,
        issuer: account.issuer,
        label: account.label,
        secret: account.secret,
        algorithm: account.algorithm,
        digits: account.digits,
        period: account.period,
        counter: account.counter,
        domains: account.domains,
        pinned: account.pinned,
      });
    } else {
      collector.warn(`Entry ${index + 1}: invalid account data.`);
    }
  });
  return collector.finish('dauthenticator');
}

/** Routes parsed JSON to the importer for its format. */
export async function importFromJson(json: unknown, options: ImportOptions = {}): Promise<ImportResult> {
  if (isDAuthBackup(json) || isEncryptedVault(json)) {
    return importDAuthBackup(json, options);
  }
  const record = asRecord(json);
  if (Array.isArray(record.services) || typeof record.servicesEncrypted === 'string') {
    return import2fas(record, options);
  }
  if (isAegisFile(json)) {
    return importAegis(json, options);
  }
  if (Array.isArray(record.items)) {
    return importBitwardenJson(record);
  }
  return importGenericJson(json);
}

function looksLikeJson(text: string): boolean {
  return /^[[{]/.test(text);
}

function csvHeaders(text: string): string[] {
  const firstRow = parseCsv(text.split(/\r?\n/, 1)[0] ?? '', detectDelimiter(text))[0];
  return (firstRow ?? []).map((h) => h.trim());
}

/** Detects the format of arbitrary text and imports it. */
export async function importFromText(input: string, options: ImportOptions = {}): Promise<ImportResult> {
  const text = input.replace(/^\uFEFF/, '').trim();
  if (!text) {
    throw new Error('Nothing to import.');
  }

  if (looksLikeJson(text)) {
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      json = undefined;
    }
    if (json !== undefined) {
      return importFromJson(json, options);
    }
  }

  if (/otpauth-migration:\/\//i.test(text)) {
    return importGoogleMigration(text);
  }

  const firstLine = text.split(/\r?\n/, 1)[0] ?? '';
  if (!isOtpAuthUri(firstLine) && /[,;\t]/.test(firstLine)) {
    const headers = csvHeaders(text);
    if (headers.includes('login_totp')) {
      return importBitwardenCsv(parseCsvObjects(text));
    }
    if (csvHeaderLooksUsable(headers)) {
      return importGenericCsvRecords(parseCsvObjects(text));
    }
  }

  if (/otpauth:\/\//i.test(text)) {
    return importOtpAuthList(text);
  }

  const cleanSecret = normalizeBase32(text);
  if (isValidBase32(cleanSecret) && cleanSecret.length >= 8) {
    const collector = new ImportCollector();
    collector.add(
      validateImported({
        type: 'totp',
        issuer: options.fileName ? options.fileName.replace(/\.[^.]+$/, '') : 'Imported Secret',
        label: '',
        secret: cleanSecret,
      }),
      'Raw Secret',
    );
    return collector.finish('generic-json');
  }

  throw new Error('Unrecognized format. Supported: otpauth:// links, Google Authenticator, 2FAS, Aegis, Bitwarden, DAuthenticator and JSON/CSV exports.');
}
