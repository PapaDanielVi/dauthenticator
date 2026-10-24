/**
 * DOM Autofill script for 2FA one-time codes.
 *
 * Locates 2FA inputs on the page via standard attributes (autocomplete="one-time-code")
 * and semantic heuristics (otp, 2fa, mfa, verification code), supporting both
 * single text fields and split 6-box single-digit input sequences. Dispatches
 * native input and change events using prototype property setters so React,
 * Vue, Angular and Svelte form frameworks catch the mutation.
 */
import type { ExtensionMessage } from '../shared/messages';

const OTP_HINTS = ['one-time-code', 'totp', 'otp', '2fa', 'mfa', 'verification', 'passcode', 'security-code', 'auth-code'];

function isVisible(el: HTMLElement): boolean {
  if (el.offsetWidth === 0 && el.offsetHeight === 0) {
    return false;
  }
  const style = window.getComputedStyle(el);
  return style.display !== 'none' && style.visibility !== 'hidden' && style.opacity !== '0';
}

function matchesHint(text: string): boolean {
  const lower = text.toLowerCase();
  return OTP_HINTS.some((hint) => lower.includes(hint));
}

function scoreInput(input: HTMLInputElement): number {
  if (input.disabled || input.readOnly || !isVisible(input)) {
    return -1;
  }
  const type = input.type.toLowerCase();
  if (type === 'hidden' || type === 'submit' || type === 'button' || type === 'checkbox' || type === 'radio' || type === 'file') {
    return -1;
  }
  let score = 0;
  if (input.autocomplete.toLowerCase() === 'one-time-code') {
    score += 100;
  }
  const checkAttrs = [input.name, input.id, input.placeholder, input.getAttribute('aria-label') ?? '', input.className];
  for (const attr of checkAttrs) {
    if (matchesHint(attr)) {
      score += 20;
    }
  }
  if (input.maxLength === 6 || input.maxLength === 8) {
    score += 15;
  }
  if (input.inputMode === 'numeric') {
    score += 10;
  }
  return score;
}

/** Finds a sequence of single-digit split inputs (e.g. 6 separate boxes). */
function findSplitInputs(): HTMLInputElement[] | null {
  const allInputs = Array.from(document.querySelectorAll<HTMLInputElement>('input:not([type="hidden"])'))
    .filter((el) => isVisible(el) && !el.disabled && !el.readOnly);

  // 1. Group inputs sharing a direct parent element
  const groups = new Map<HTMLElement, HTMLInputElement[]>();
  for (const input of allInputs) {
    const parent = input.parentElement;
    if (parent) {
      const list = groups.get(parent) ?? [];
      list.push(input);
      groups.set(parent, list);
    }
  }

  for (const list of groups.values()) {
    if (list.length >= 4 && list.length <= 8) {
      const isSplitSequence = list.every((el) => {
        const isSingleOrSmall = el.maxLength === 1 || el.size === 1;
        const isNumeric = el.inputMode === 'numeric' || el.type === 'number' || el.type === 'text' || el.type === 'tel';
        const matchesName = matchesHint(el.name) || matchesHint(el.id) || matchesHint(el.className);
        return (isSingleOrSmall && isNumeric) || matchesName;
      });
      if (isSplitSequence) {
        return list;
      }
    }
  }

  // 2. Scan consecutive single-character input boxes (even if individually wrapped in div/span)
  let currentRun: HTMLInputElement[] = [];
  for (const el of allInputs) {
    const isSingle =
      (el.maxLength === 1 || el.size === 1) &&
      (el.inputMode === 'numeric' ||
        el.type === 'number' ||
        el.type === 'text' ||
        el.type === 'tel' ||
        matchesHint(el.name) ||
        matchesHint(el.id));
    if (isSingle) {
      currentRun.push(el);
    } else {
      if (currentRun.length >= 4 && currentRun.length <= 8) {
        return currentRun;
      }
      currentRun = [];
    }
  }
  if (currentRun.length >= 4 && currentRun.length <= 8) {
    return currentRun;
  }

  return null;
}

/** Dispatches React/Vue/Angular compatible value change events. */
function setNativeValue(element: HTMLInputElement, value: string): void {
  const valueDescriptor = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value');
  if (valueDescriptor?.set) {
    valueDescriptor.set.call(element, value);
  } else {
    element.value = value;
  }

  element.dispatchEvent(new Event('input', { bubbles: true, cancelable: true }));
  element.dispatchEvent(new Event('change', { bubbles: true, cancelable: true }));
}

function flashHighlight(elements: HTMLElement[]): void {
  const originalBorders = elements.map((el) => el.style.outline);
  for (const el of elements) {
    el.style.outline = '2px solid #22c55e';
    el.style.outlineOffset = '2px';
  }
  setTimeout(() => {
    elements.forEach((el, index) => {
      el.style.outline = originalBorders[index] ?? '';
      el.style.outlineOffset = '';
    });
  }, 1500);
}

export function performAutofill(rawCode: string): { success: boolean; fieldsFilled: number; reason?: string } {
  const cleanCode = rawCode.replace(/\s+/g, '');
  if (!cleanCode) {
    return { success: false, fieldsFilled: 0, reason: 'Empty code' };
  }

  // 1. Check for split inputs first
  const splitBoxes = findSplitInputs();
  if (splitBoxes && splitBoxes.length >= cleanCode.length) {
    splitBoxes.forEach((input, index) => {
      const char = cleanCode[index] ?? '';
      input.focus();
      setNativeValue(input, char);
      input.dispatchEvent(new KeyboardEvent('keydown', { key: char, code: `Digit${char}`, bubbles: true }));
      input.dispatchEvent(new KeyboardEvent('keyup', { key: char, code: `Digit${char}`, bubbles: true }));
    });
    flashHighlight(splitBoxes);
    const last = splitBoxes[cleanCode.length - 1];
    last?.focus();
    return { success: true, fieldsFilled: cleanCode.length };
  }

  // 2. Look for best candidate input
  const inputs = Array.from(document.querySelectorAll<HTMLInputElement>('input'))
    .map((el) => ({ el, score: scoreInput(el) }))
    .filter((entry) => entry.score > 0)
    .sort((a, b) => b.score - a.score);

  const best = inputs[0];
  if (best) {
    best.el.focus();
    setNativeValue(best.el, cleanCode);
    flashHighlight([best.el]);
    return { success: true, fieldsFilled: 1 };
  }

  // 3. Fallback: if user is currently focused on an editable input, fill it directly
  const active = document.activeElement;
  if (active instanceof HTMLInputElement && isVisible(active) && !active.readOnly && !active.disabled) {
    active.focus();
    setNativeValue(active, cleanCode);
    flashHighlight([active]);
    return { success: true, fieldsFilled: 1 };
  }

  return { success: false, fieldsFilled: 0, reason: 'No 2FA input field detected' };
}

// Global listener for messages dispatched from popup or background script
chrome.runtime.onMessage.addListener((message: ExtensionMessage, _sender, sendResponse) => {
  if (message.type === 'FILL_CODE') {
    const result = performAutofill(message.code);
    sendResponse({ type: 'AUTOFILL_STATUS', ...result });
  }
  return true;
});
