/**
 * Entry point for every import path: QR images, raw text and backup files.
 */
import { decodeAllQrFromBlob } from './qr';
import { importFromText } from './fileImporters';
import type { ImportOptions, ImportResult } from './types';

export { importFromText } from './fileImporters';
export { decodeAllQrFromBlob, decodeQrFromBlob } from './qr';
export { SOURCE_LABELS } from './types';
export type { ImportOptions, ImportResult, ImportSource, BatchInfo } from './types';

const IMAGE_EXTENSIONS = /\.(png|jpe?g|gif|webp|bmp|avif)$/i;
/** Backups larger than this are almost certainly not authenticator exports. */
const MAX_TEXT_FILE_BYTES = 20 * 1024 * 1024;

export function isImageFile(file: File): boolean {
  return file.type.startsWith('image/') || IMAGE_EXTENSIONS.test(file.name);
}

/** Decodes one or more QR codes in an image and imports whatever they contain. */
export async function importFromImage(image: Blob, options: ImportOptions = {}): Promise<ImportResult> {
  const codes = await decodeAllQrFromBlob(image);
  if (codes.length === 0) {
    throw new Error('No QR code was found in the image.');
  }
  return importFromText(codes.join('\n'), options);
}

/** Imports an uploaded or dropped file: QR images and any supported backup format. */
export async function importFromFile(file: File, options: ImportOptions = {}): Promise<ImportResult> {
  if (isImageFile(file)) {
    return importFromImage(file, options);
  }
  if (file.size > MAX_TEXT_FILE_BYTES) {
    throw new Error('That file is too large to be an authenticator backup.');
  }
  return importFromText(await file.text(), { ...options, fileName: file.name });
}
