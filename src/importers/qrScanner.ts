/**
 * Live Webcam QR Scanner for single and batch 2FA migrations.
 * Uses navigator.mediaDevices.getUserMedia and OffscreenCanvas with jsQR.
 */
import { binarizeImageData, decodeQrImageData } from './qr';

export type QrDetectionCallback = (text: string) => void;
export type QrErrorCallback = (err: Error) => void;

export class WebcamScanner {
  private stream: MediaStream | null = null;
  private animId: number | null = null;
  private timerId: number | null = null;
  private canvas: OffscreenCanvas | null = null;
  private ctx: OffscreenCanvasRenderingContext2D | null = null;
  private active = false;
  private lastScanTime = 0;
  private scanIntervalMs = 90;

  async start(videoEl: HTMLVideoElement, onDetected: QrDetectionCallback, onError?: QrErrorCallback): Promise<void> {
    if (this.active) {
      this.stop();
    }
    if (!navigator.mediaDevices?.getUserMedia) {
      throw new Error('Webcam access is not supported by this browser environment.');
    }

    try {
      // Prefer rear/environment camera on phones, fallback to default camera
      try {
        this.stream = await navigator.mediaDevices.getUserMedia({
          video: { facingMode: 'environment', width: { ideal: 1280 }, height: { ideal: 720 } },
          audio: false,
        });
      } catch {
        this.stream = await navigator.mediaDevices.getUserMedia({
          video: true,
          audio: false,
        });
      }

      videoEl.srcObject = this.stream;
      await videoEl.play();

      this.active = true;
      this.loop(videoEl, onDetected);
    } catch (err) {
      this.stop();
      if (onError) onError(err as Error);
      throw err;
    }
  }

  private loop(videoEl: HTMLVideoElement, onDetected: QrDetectionCallback): void {
    const scan = () => {
      if (!this.active) return;

      const now = Date.now();
      if (now - this.lastScanTime >= this.scanIntervalMs) {
        this.lastScanTime = now;
        if (videoEl.readyState >= HTMLMediaElement.HAVE_CURRENT_DATA && videoEl.videoWidth > 0 && videoEl.videoHeight > 0) {
          const width = videoEl.videoWidth;
          const height = videoEl.videoHeight;

          if (!this.canvas || this.canvas.width !== width || this.canvas.height !== height) {
            this.canvas = new OffscreenCanvas(width, height);
            this.ctx = this.canvas.getContext('2d', { willReadFrequently: true });
          }

          if (this.ctx) {
            this.ctx.drawImage(videoEl, 0, 0, width, height);
            const frame = this.ctx.getImageData(0, 0, width, height);
            let code = decodeQrImageData(frame);
            if (!code) {
              // Try contrast-enhanced binarization for dense phone screen exports
              const binarized = binarizeImageData(frame);
              code = decodeQrImageData(binarized);
            }
            if (code) {
              onDetected(code.trim());
            }
          }
        }
      }

      if (this.active) {
        this.animId = requestAnimationFrame(scan);
      }
    };

    this.animId = requestAnimationFrame(scan);
  }

  stop(): void {
    this.active = false;
    if (this.animId !== null) {
      cancelAnimationFrame(this.animId);
      this.animId = null;
    }
    if (this.timerId !== null) {
      clearInterval(this.timerId);
      this.timerId = null;
    }
    if (this.stream) {
      this.stream.getTracks().forEach((track) => track.stop());
      this.stream = null;
    }
    this.canvas = null;
    this.ctx = null;
  }

  get isRunning(): boolean {
    return this.active;
  }
}
