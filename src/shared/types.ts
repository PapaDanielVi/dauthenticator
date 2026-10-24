/** Hash algorithms supported by the OTP engine, named as Web Crypto expects them. */
export type HashAlgorithm = 'SHA-1' | 'SHA-256' | 'SHA-512';

/** OTP flavour: time based (RFC 6238) or counter based (RFC 4226). */
export type OtpType = 'totp' | 'hotp';

/** Number of digits in a generated code. The UI offers 6 and 8, imports may carry 7. */
export type Digits = 6 | 7 | 8;

/** A single 2FA account as stored inside the encrypted vault. */
export interface AccountEntry {
  id: string;
  type: OtpType;
  issuer: string;
  /** Account name, usually an email address or username. */
  label: string;
  /** Base32 secret, upper case, without padding or whitespace. */
  secret: string;
  algorithm: HashAlgorithm;
  digits: Digits;
  /** TOTP step in seconds. Ignored for HOTP. */
  period: number;
  /** HOTP moving factor. Ignored for TOTP. */
  counter: number;
  /** Hostnames this account should autofill on, e.g. "github.com". */
  domains: string[];
  /** Pinned accounts remain sorted at the top of the list. */
  pinned?: boolean;
  createdAt: number;
  updatedAt: number;
}

/** Account data produced by importers before it gets an id and timestamps. */
export type ImportedAccount = Omit<AccountEntry, 'id' | 'domains' | 'createdAt' | 'updatedAt' | 'pinned'> & {
  domains?: string[];
  pinned?: boolean;
};

/** Plaintext vault structure. Only ever held in memory, never persisted unencrypted. */
export interface VaultData {
  version: 1;
  accounts: AccountEntry[];
}

/** Non-secret user preferences, stored in plain chrome.storage.local. */
export interface Settings {
  /** Minutes of inactivity before the session key is wiped. 0 disables the timer. */
  autoLockMinutes: number;
  /** Wipe the session key when the operating system locks the screen. */
  lockOnSystemLock: boolean;
  /** Mirror the encrypted vault to chrome.storage.sync after every change. */
  autoSync: boolean;
  /** Remember the site's hostname on an account after filling it from the popup. */
  learnDomains: boolean;
  lastSyncAt: number | null;
  lastSyncError: string | null;
}

export const DEFAULT_SETTINGS: Settings = {
  autoLockMinutes: 15,
  lockOnSystemLock: true,
  autoSync: false,
  learnDomains: true,
  lastSyncAt: null,
  lastSyncError: null,
};
