/**
 * QR code decoding for screenshots, uploaded images and camera frames, using
 * jsQR on raw RGBA pixels from an OffscreenCanvas.
 */
import jsQR from 'jsqr';
import { base64ToBytes } from '../crypto/encoding';

/** Screenshots wider than this get a second, downscaled decoding pass. */
const DOWNSCALE_THRESHOLD = 1600;
const DOWNSCALE_FACTOR = 0.5;

export function decodeQrImageData(image: ImageData): string | null {
  const result = jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' });
  return result?.data ? result.data : null;
}

function drawScaled(bitmap: ImageBitmap, scale: number): ImageData {
  const width = Math.max(1, Math.round(bitmap.width * scale));
  const height = Math.max(1, Math.round(bitmap.height * scale));
  const canvas = new OffscreenCanvas(width, height);
  const ctx = canvas.getContext('2d', { willReadFrequently: true });
  if (!ctx) {
    throw new Error('Canvas 2D context is not available.');
  }
  ctx.imageSmoothingEnabled = scale < 1;
  ctx.drawImage(bitmap, 0, 0, width, height);
  return ctx.getImageData(0, 0, width, height);
}

/** Decodes the first QR code found in an image bitmap. */
export function decodeQrFromBitmap(bitmap: ImageBitmap): string | null {
  const scales = [1];
  if (Math.max(bitmap.width, bitmap.height) > DOWNSCALE_THRESHOLD) {
    scales.push(DOWNSCALE_FACTOR);
  }
  for (const scale of scales) {
    const text = decodeQrImageData(drawScaled(bitmap, scale));
    if (text) {
      return text;
    }
  }
  return null;
}

export async function decodeQrFromBlob(blob: Blob): Promise<string | null> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(blob);
  } catch {
    throw new Error('That file could not be read as an image.');
  }
  try {
    return decodeQrFromBitmap(bitmap);
  } finally {
    bitmap.close();
  }
}

/** Converts a data: URL (as returned by captureVisibleTab) into a Blob without fetch. */
export function dataUrlToBlob(dataUrl: string): Blob {
  const match = /^data:([^;,]+)?(;base64)?,(.*)$/s.exec(dataUrl);
  if (!match) {
    throw new Error('Invalid data URL.');
  }
  const mime = match[1] ?? 'application/octet-stream';
  const payload = match[3] ?? '';
  const bytes = match[2] ? base64ToBytes(payload) : new TextEncoder().encode(decodeURIComponent(payload));
  return new Blob([bytes], { type: mime });
}

/**
 * Screenshots the visible area of the active tab and decodes a QR code from it.
 * Relies on the activeTab grant the popup receives when the user opens it.
 */
export async function scanVisibleTabForQr(): Promise<string | null> {
  const dataUrl = await chrome.tabs.captureVisibleTab(chrome.windows.WINDOW_ID_CURRENT, { format: 'png' });
  return decodeQrFromBlob(dataUrlToBlob(dataUrl));
}
