/**
 * Structured messages exchanged between background, popup and content scripts.
 */

export interface FillCodeMessage {
  type: 'FILL_CODE';
  code: string;
}

export interface AutofillStatusMessage {
  type: 'AUTOFILL_STATUS';
  success: boolean;
  fieldsFilled: number;
  reason?: string;
}

export type ExtensionMessage = FillCodeMessage | AutofillStatusMessage;

export function isFillCodeMessage(value: unknown): value is FillCodeMessage {
  return (
    typeof value === 'object' &&
    value !== null &&
    (value as Record<string, unknown>).type === 'FILL_CODE' &&
    typeof (value as Record<string, unknown>).code === 'string'
  );
}
