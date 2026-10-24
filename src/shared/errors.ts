/** Which kind of encrypted payload needs a password, so the UI can word the prompt. */
export type PasswordKind = 'dauthenticator' | 'aegis' | '2fas' | 'sync';

/** Thrown when a payload is encrypted and no (or no matching) password was supplied. */
export class PasswordRequiredError extends Error {
  readonly kind: PasswordKind;
  readonly wrongPassword: boolean;

  constructor(kind: PasswordKind, wrongPassword = false) {
    super(wrongPassword ? 'That password did not decrypt the backup.' : 'This backup is encrypted. Enter its password.');
    this.name = 'PasswordRequiredError';
    this.kind = kind;
    this.wrongPassword = wrongPassword;
  }
}

/** Extracts a readable message from anything thrown. */
export function errorMessage(error: unknown): string {
  if (error instanceof Error) {
    return error.message;
  }
  return typeof error === 'string' ? error : 'Unexpected error.';
}
