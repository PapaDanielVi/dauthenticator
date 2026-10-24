/**
 * Generates extension icons in 16x16, 32x32, 48x48, and 128x128 PNG formats
 * using only standard Node.js built-in modules (zlib, fs, path).
 */
import fs from 'node:fs';
import path from 'node:path';
import zlib from 'node:zlib';

function crc32(buf) {
  let c;
  let crcTable = [];
  for (let n = 0; n < 256; n++) {
    c = n;
    for (let k = 0; k < 8; k++) {
      c = (c & 1) ? (0xedb88320 ^ (c >>> 1)) : (c >>> 1);
    }
    crcTable[n] = c;
  }
  let crc = 0 ^ (-1);
  for (let i = 0; i < buf.length; i++) {
    crc = (crc >>> 8) ^ crcTable[(crc ^ buf[i]) & 0xff];
  }
  return (crc ^ (-1)) >>> 0;
}

function makeChunk(type, data) {
  const len = Buffer.alloc(4);
  len.writeUInt32BE(data.length, 0);
  const typeBuf = Buffer.from(type, 'ascii');
  const body = Buffer.concat([typeBuf, data]);
  const crcBuf = Buffer.alloc(4);
  crcBuf.writeUInt32BE(crc32(body), 0);
  return Buffer.concat([len, body, crcBuf]);
}

function createPng(width, height, rgbaBuffer) {
  const signature = Buffer.from([137, 80, 78, 71, 13, 10, 26, 10]);

  // IHDR
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr.writeUInt8(8, 8); // bit depth 8
  ihdr.writeUInt8(6, 9); // RGBA
  ihdr.writeUInt8(0, 10); // compression
  ihdr.writeUInt8(0, 11); // filter
  ihdr.writeUInt8(0, 12); // interlace

  // Scanlines with filter byte 0
  const scanlines = Buffer.alloc(height * (width * 4 + 1));
  let srcOffset = 0;
  let dstOffset = 0;
  for (let y = 0; y < height; y++) {
    scanlines[dstOffset++] = 0; // filter None
    rgbaBuffer.copy(scanlines, dstOffset, srcOffset, srcOffset + width * 4);
    dstOffset += width * 4;
    srcOffset += width * 4;
  }

  const idatData = zlib.deflateSync(scanlines, { level: 9 });
  const idatChunk = makeChunk('IDAT', idatData);
  const ihdrChunk = makeChunk('IHDR', ihdr);
  const iendChunk = makeChunk('IEND', Buffer.alloc(0));

  return Buffer.concat([signature, ihdrChunk, idatChunk, iendChunk]);
}

/** Draws the DAuthenticator icon: rounded shield badge with an inner keyhole / vault symbol. */
function drawIcon(size) {
  const buf = Buffer.alloc(size * size * 4);

  function setPixel(x, y, r, g, b, a) {
    if (x < 0 || x >= size || y < 0 || y >= size) return;
    const idx = (y * size + x) * 4;
    // Simple alpha blending
    const srcA = a / 255;
    const dstA = buf[idx + 3] / 255;
    const outA = srcA + dstA * (1 - srcA);
    if (outA > 0) {
      buf[idx] = Math.round((r * srcA + buf[idx] * dstA * (1 - srcA)) / outA);
      buf[idx + 1] = Math.round((g * srcA + buf[idx + 1] * dstA * (1 - srcA)) / outA);
      buf[idx + 2] = Math.round((b * srcA + buf[idx + 2] * dstA * (1 - srcA)) / outA);
      buf[idx + 3] = Math.round(outA * 255);
    }
  }

  const center = size / 2;
  const radius = size * 0.44;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      // Rounded shield-squircle background
      const dx = Math.abs(x - center + 0.5);
      const dy = Math.abs(y - center + 0.5);
      const dist = Math.sqrt(dx * dx + dy * dy);

      // Squircle distance
      const squircle = Math.pow(dx / radius, 3.2) + Math.pow(dy / radius, 3.2);

      if (squircle <= 1.05) {
        // Gradient from Indigo-600 (#4f46e5) to Violet-600 (#7c3aed)
        const t = (x + y) / (2 * size);
        const r = Math.round(79 * (1 - t) + 124 * t);
        const g = Math.round(70 * (1 - t) + 58 * t);
        const b = Math.round(229 * (1 - t) + 237 * t);

        let alpha = 255;
        if (squircle > 0.95) {
          alpha = Math.round(255 * (1.05 - squircle) / 0.1);
        }
        setPixel(x, y, r, g, b, Math.max(0, Math.min(255, alpha)));
      }
    }
  }

  // Draw inner shield/keyhole symbol in crisp white
  const keyCenterY = center - size * 0.08;
  const keyRadius = size * 0.15;

  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = x - center + 0.5;
      const dyCircle = y - keyCenterY + 0.5;
      const circleDist = Math.sqrt(dx * dx + dyCircle * dyCircle);

      let isInsideKey = false;
      // Head of the key / lock shackle
      if (circleDist <= keyRadius) {
        isInsideKey = true;
      }
      // Stem / body of the key
      const stemTop = keyCenterY;
      const stemBottom = center + size * 0.22;
      const stemHalfWidth = size * 0.08;
      if (y >= stemTop && y <= stemBottom && Math.abs(dx) <= stemHalfWidth) {
        isInsideKey = true;
      }
      // Key teeth / base
      const toothTop = center + size * 0.12;
      const toothBottom = center + size * 0.22;
      const toothRight = size * 0.18;
      if (y >= toothTop && y <= toothBottom && dx >= 0 && dx <= toothRight) {
        isInsideKey = true;
      }

      if (isInsideKey) {
        // Antialiased edge
        setPixel(x, y, 255, 255, 255, 255);
      }
    }
  }

  // Draw center hole inside top circle
  const holeRadius = keyRadius * 0.45;
  for (let y = 0; y < size; y++) {
    for (let x = 0; x < size; x++) {
      const dx = x - center + 0.5;
      const dyCircle = y - keyCenterY + 0.5;
      const circleDist = Math.sqrt(dx * dx + dyCircle * dyCircle);
      if (circleDist <= holeRadius) {
        // Cutout back to background gradient
        const t = (x + y) / (2 * size);
        const r = Math.round(79 * (1 - t) + 124 * t);
        const g = Math.round(70 * (1 - t) + 58 * t);
        const b = Math.round(229 * (1 - t) + 237 * t);
        setPixel(x, y, r, g, b, 255);
      }
    }
  }

  return buf;
}

const outDir = path.resolve('public/icons');
fs.mkdirSync(outDir, { recursive: true });

for (const size of [16, 32, 48, 128]) {
  const rgba = drawIcon(size);
  const png = createPng(size, size, rgba);
  fs.writeFileSync(path.join(outDir, `icon-${size}.png`), png);
  console.log(`Generated public/icons/icon-${size}.png (${size}x${size})`);
}
