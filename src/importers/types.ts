import type { ImportedAccount } from '../shared/types';

/** Human readable name of the format an import was recognised as. */
export type ImportSource =
  | 'otpauth'
  | 'google-migration'
  | '2fas'
  | 'aegis'
  | 'bitwarden-json'
  | 'bitwarden-csv'
  | 'dauthenticator'
  | 'generic-json'
  | 'generic-csv';

export const SOURCE_LABELS: Readonly<Record<ImportSource, string>> = {
  otpauth: 'otpauth:// links',
  'google-migration': 'Google Authenticator export',
  '2fas': '2FAS backup',
  aegis: 'Aegis backup',
  'bitwarden-json': 'Bitwarden JSON export',
  'bitwarden-csv': 'Bitwarden CSV export',
  dauthenticator: 'DAuthenticator backup',
  'generic-json': 'JSON export',
  'generic-csv': 'CSV export',
};

/** Position of a QR code inside a multi-part Google Authenticator export. */
export interface BatchInfo {
  id: number;
  index: number;
  size: number;
}

export interface ImportResult {
  source: ImportSource;
  accounts: ImportedAccount[];
  /** Entries that were skipped, with the reason. */
  warnings: string[];
  batch?: BatchInfo;
}

export interface ImportOptions {
  /** Password for encrypted Aegis, 2FAS or DAuthenticator backups. */
  password?: string;
  /** Original file name, used as a format hint. */
  fileName?: string;
}

/** Collects valid accounts and warnings while walking a backup. */
export class ImportCollector {
  readonly accounts: ImportedAccount[] = [];
  readonly warnings: string[] = [];

  add(result: ImportedAccount | string, context: string): void {
    if (typeof result === 'string') {
      this.warnings.push(`${context}: ${result}`);
    } else {
      this.accounts.push(result);
    }
  }

  warn(message: string): void {
    this.warnings.push(message);
  }

  finish(source: ImportSource, batch?: BatchInfo): ImportResult {
    return batch ? { source, accounts: this.accounts, warnings: this.warnings, batch } : { source, accounts: this.accounts, warnings: this.warnings };
  }
}
