/**
 * QR code decoding for screenshots, uploaded images and camera frames, using
 * jsQR on raw RGBA pixels from an OffscreenCanvas.
 * Supports dense Google Authenticator migration codes, multi-QR image detection,
 * contrast enhancement and scaling passes.
 */
import jsQR from 'jsqr';
import { base64ToBytes } from '../crypto/encoding';

export function decodeQrImageData(image: ImageData): string | null {
  const result = jsQR(image.data, image.width, image.height, { inversionAttempts: 'attemptBoth' });
  return result?.data ? result.data : null;
}

/** Masks a detected QR code region so subsequent passes can detect other QR codes. */
function maskBoundingBox(
  image: ImageData,
  loc: {
    topLeftCorner: { x: number; y: number };
    topRightCorner: { x: number; y: number };
    bottomRightCorner: { x: number; y: number };
    bottomLeftCorner: { x: number; y: number };
  },
): void {
  const xs = [loc.topLeftCorner.x, loc.topRightCorner.x, loc.bottomRightCorner.x, loc.bottomLeftCorner.x];
  const ys = [loc.topLeftCorner.y, loc.topRightCorner.y, loc.bottomRightCorner.y, loc.bottomLeftCorner.y];
  const minX = Math.max(0, Math.floor(Math.min(...xs)) - 6);
  const maxX = Math.min(image.width - 1, Math.ceil(Math.max(...xs)) + 6);
  const minY = Math.max(0, Math.floor(Math.min(...ys)) - 6);
  const maxY = Math.min(image.height - 1, Math.ceil(Math.max(...ys)) + 6);

  for (let y = minY; y <= maxY; y++) {
    for (let x = minX; x <= maxX; x++) {
      const idx = (y * image.width + x) * 4;
      image.data[idx] = 255;
      image.data[idx + 1] = 255;
      image.data[idx + 2] = 255;
      image.data[idx + 3] = 255;
    }
  }
}

/** Contrast-adaptive binarization pass for low-contrast phone photos or dark mode screenshots. */
export function binarizeImageData(src: ImageData): ImageData {
  const dst = new ImageData(new Uint8ClampedArray(src.data), src.width, src.height);
  let sum = 0;
  const len = src.width * src.height;
  for (let i = 0; i < len; i++) {
    const idx = i * 4;
    sum += ((src.data[idx] as number) * 299 + (src.data[idx + 1] as number) * 587 + (src.data[idx + 2] as number) * 114) / 1000;
  }
  const avg = sum / len;
  for (let i = 0; i < len; i++) {
    const idx = i * 4;
    const lum = ((src.data[idx] as number) * 299 + (src.data[idx + 1] as number) * 587 + (src.data[idx + 2] as number) * 114) / 1000;
    const val = lum < avg ? 0 : 255;
    dst.data[idx] = val;
    dst.data[idx + 1] = val;
    dst.data[idx + 2] = val;
    dst.data[idx + 3] = 255;
  }
  return dst;
}

/** Decodes all distinct QR codes found in an ImageData frame by iteratively masking detected regions. */
export function decodeAllQrFromImageData(image: ImageData, maxCodes = 12): string[] {
  const codes: string[] = [];
  const copy = new ImageData(new Uint8ClampedArray(image.data), image.width, image.height);

  for (let i = 0; i < maxCodes; i++) {
    const res = jsQR(copy.data, copy.width, copy.height, { inversionAttempts: 'attemptBoth' });
    if (!res?.data) break;
    const text = res.data.trim();
    if (text && !codes.includes(text)) {
      codes.push(text);
    }
    maskBoundingBox(copy, res.location);
  }
  return codes;
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

/** Decodes all distinct QR codes found across multiple scale and contrast passes. */
export function decodeAllQrFromBitmap(bitmap: ImageBitmap): string[] {
  const results = new Set<string>();
  const maxDim = Math.max(bitmap.width, bitmap.height);
  const scales: number[] = [1.0];

  if (maxDim > 2000) {
    scales.push(0.5, 0.75);
  } else if (maxDim > 1200) {
    scales.push(0.75, 0.5);
  }

  for (const scale of scales) {
    const imgData = drawScaled(bitmap, scale);
    const found = decodeAllQrFromImageData(imgData);
    for (const code of found) {
      results.add(code);
    }
    if (results.size === 0) {
      // Try high-contrast binarization pass
      const binarized = binarizeImageData(imgData);
      const binFound = decodeAllQrFromImageData(binarized);
      for (const code of binFound) {
        results.add(code);
      }
    }
  }

  return [...results];
}

/** Decodes the first QR code found in an image bitmap. */
export function decodeQrFromBitmap(bitmap: ImageBitmap): string | null {
  const all = decodeAllQrFromBitmap(bitmap);
  return all[0] ?? null;
}

export async function decodeAllQrFromBlob(blob: Blob): Promise<string[]> {
  let bitmap: ImageBitmap;
  try {
    bitmap = await createImageBitmap(blob);
  } catch {
    throw new Error('That file could not be read as an image.');
  }
  try {
    return decodeAllQrFromBitmap(bitmap);
  } finally {
    bitmap.close();
  }
}

export async function decodeQrFromBlob(blob: Blob): Promise<string | null> {
  const all = await decodeAllQrFromBlob(blob);
  return all[0] ?? null;
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
 * Screenshots the visible area of the active tab and decodes any QR codes from it.
 * If multiple QR codes are found, they are returned joined by newlines.
 */
export async function scanVisibleTabForQr(): Promise<string | null> {
  const dataUrl = await chrome.tabs.captureVisibleTab(chrome.windows.WINDOW_ID_CURRENT, { format: 'png' });
  const codes = await decodeAllQrFromBlob(dataUrlToBlob(dataUrl));
  if (codes.length === 0) {
    return null;
  }
  return codes.join('\n');
}
