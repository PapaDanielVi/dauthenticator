/**
 * Entry point for every import path: QR images, raw text and backup files.
 */
import { decodeQrFromBlob } from './qr';
import { importFromText } from './fileImporters';
import type { ImportOptions, ImportResult } from './types';

export { importFromText } from './fileImporters';
export { SOURCE_LABELS } from './types';
export type { ImportOptions, ImportResult, ImportSource, BatchInfo } from './types';

const IMAGE_EXTENSIONS = /\.(png|jpe?g|gif|webp|bmp|avif)$/i;
/** Backups larger than this are almost certainly not authenticator exports. */
const MAX_TEXT_FILE_BYTES = 20 * 1024 * 1024;

export function isImageFile(file: File): boolean {
  return file.type.startsWith('image/') || IMAGE_EXTENSIONS.test(file.name);
}

/** Decodes a QR code in an image and imports whatever it contains. */
export async function importFromImage(image: Blob, options: ImportOptions = {}): Promise<ImportResult> {
  const text = await decodeQrFromBlob(image);
  if (!text) {
    throw new Error('No QR code was found in the image.');
  }
  return importFromText(text, options);
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
