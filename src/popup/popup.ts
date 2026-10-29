/**
 * Popup UI Controller for DAuthenticator.
 */
import {
  hasVault,
  isUnlocked,
  createVault,
  unlockVault,
  lockVault,
  loadVault,
  WrongPasswordError,
} from '../crypto/vault';
import { hasBiometrics } from '../crypto/biometrics';
import { hasPin, unlockWithPin } from '../crypto/pin';
import {
  generateCode,
  formatCode,
  secondsRemaining,
  DEFAULT_PERIOD,
  DEFAULT_DIGITS,
  DEFAULT_ALGORITHM,
  type OtpParams,
} from '../crypto/totp';
import { sortAccounts, displayName, validateImported } from '../shared/accounts';
import { hostnameFromUrl, matchAccounts, pickAutofillAccount } from '../shared/match';
import { getSettings } from '../shared/settings';
import {
  addAccounts,
  deleteAccount,
  editAccount,
  consumeHotp,
  rememberDomain,
  togglePinAccount,
} from '../shared/vaultOps';
import { scanVisibleTabForQr } from '../importers/qr';
import { WebcamScanner } from '../importers/qrScanner';
import { importFromImage, importFromText } from '../importers';
import type { AccountEntry, ImportedAccount } from '../shared/types';
import type { FillCodeMessage } from '../shared/messages';

// DOM Elements
const viewSetup = document.getElementById('view-setup') as HTMLElement;
const viewUnlock = document.getElementById('view-unlock') as HTMLElement;
const viewMain = document.getElementById('view-main') as HTMLElement;

const formSetup = document.getElementById('form-setup') as HTMLFormElement;
const setupPassword = document.getElementById('setup-password') as HTMLInputElement;
const setupConfirm = document.getElementById('setup-confirm') as HTMLInputElement;
const setupError = document.getElementById('setup-error') as HTMLElement;

const formUnlock = document.getElementById('form-unlock') as HTMLFormElement;
const unlockPassword = document.getElementById('unlock-password') as HTMLInputElement;
const unlockCaps = document.getElementById('unlock-caps') as HTMLElement;
const unlockError = document.getElementById('unlock-error') as HTMLElement;

const cardUnlockBio = document.getElementById('card-unlock-bio') as HTMLElement;
const btnUnlockBiometric = document.getElementById('btn-unlock-biometric') as HTMLButtonElement;
const unlockBioError = document.getElementById('unlock-bio-error') as HTMLElement;

const formUnlockPin = document.getElementById('form-unlock-pin') as HTMLFormElement;
const unlockPin = document.getElementById('unlock-pin') as HTMLInputElement;
const unlockPinError = document.getElementById('unlock-pin-error') as HTMLElement;

const btnSwitchBio = document.getElementById('btn-switch-bio') as HTMLButtonElement;
const btnSwitchPin = document.getElementById('btn-switch-pin') as HTMLButtonElement;
const btnSwitchPwd = document.getElementById('btn-switch-pwd') as HTMLButtonElement;

const btnScanScreen = document.getElementById('btn-scan-screen') as HTMLButtonElement;
const btnUploadQrImage = document.getElementById('btn-upload-qr-image') as HTMLButtonElement;
const headerQrFileInput = document.getElementById('header-qr-file-input') as HTMLInputElement;
const btnScanCamera = document.getElementById('btn-scan-camera') as HTMLButtonElement;
const btnAddAccount = document.getElementById('btn-add-account') as HTMLButtonElement;
const btnOpenOptions = document.getElementById('btn-open-options') as HTMLButtonElement;
const btnLockVault = document.getElementById('btn-lock-vault') as HTMLButtonElement;

// Camera modal elements
const modalCamera = document.getElementById('modal-camera') as HTMLElement;
const modalCameraClose = document.getElementById('modal-camera-close') as HTMLButtonElement;
const cameraVideo = document.getElementById('camera-video') as HTMLVideoElement;
const cameraStatus = document.getElementById('camera-status') as HTMLElement;
const cameraBatchBanner = document.getElementById('camera-batch-banner') as HTMLElement;
const btnCameraCancel = document.getElementById('btn-camera-cancel') as HTMLButtonElement;
const btnCameraFinish = document.getElementById('btn-camera-finish') as HTMLButtonElement;
const cameraBatchCount = document.getElementById('camera-batch-count') as HTMLElement;

const searchInput = document.getElementById('search-input') as HTMLInputElement;
const btnSearchClear = document.getElementById('btn-search-clear') as HTMLButtonElement;
const btnToggleAllVisibility = document.getElementById('btn-toggle-all-visibility') as HTMLButtonElement;

const tabSuggestBanner = document.getElementById('tab-suggest-banner') as HTMLElement;
const suggestDomain = document.getElementById('suggest-domain') as HTMLElement;
const btnSuggestAutofill = document.getElementById('btn-suggest-autofill') as HTMLButtonElement;

const accountsList = document.getElementById('accounts-list') as HTMLElement;
const accountsEmpty = document.getElementById('accounts-empty') as HTMLElement;

const modalAccount = document.getElementById('modal-account') as HTMLElement;
const modalTitle = document.getElementById('modal-title') as HTMLElement;
const modalClose = document.getElementById('modal-close') as HTMLButtonElement;
const formAccount = document.getElementById('form-account') as HTMLFormElement;
const accountIdInput = document.getElementById('account-id') as HTMLInputElement;
const accIssuer = document.getElementById('acc-issuer') as HTMLInputElement;
const accLabel = document.getElementById('acc-label') as HTMLInputElement;
const accSecret = document.getElementById('acc-secret') as HTMLInputElement;
const accType = document.getElementById('acc-type') as HTMLSelectElement;
const accAlgo = document.getElementById('acc-algo') as HTMLSelectElement;
const accDigits = document.getElementById('acc-digits') as HTMLSelectElement;
const accPeriod = document.getElementById('acc-period') as HTMLInputElement;
const accCounter = document.getElementById('acc-counter') as HTMLInputElement;
const groupPeriod = document.getElementById('group-period') as HTMLElement;
const groupCounter = document.getElementById('group-counter') as HTMLElement;
const accDomains = document.getElementById('acc-domains') as HTMLInputElement;
const accPinned = document.getElementById('acc-pinned') as HTMLInputElement;
const accountError = document.getElementById('account-error') as HTMLElement;
const btnCancelAccount = document.getElementById('btn-cancel-account') as HTMLButtonElement;

const addModalTabs = document.getElementById('add-modal-tabs') as HTMLElement;
const qrDropzone = document.getElementById('qr-dropzone') as HTMLElement;
const qrFileInput = document.getElementById('qr-file-input') as HTMLInputElement;
const qrDropStatus = document.getElementById('qr-drop-status') as HTMLElement;

const toastEl = document.getElementById('toast') as HTMLElement;

// State
let accounts: AccountEntry[] = [];
let currentHostname: string | null = null;
let currentTabId: number | null = null;
let activeMatchedAccount: AccountEntry | null = null;
let searchQuery = '';
let timerInterval: number | null = null;
const revealedAccountIds = new Set<string>();

const EYE_SVG = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
const EYE_OFF_SVG = `<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;

function maskedCode(digits: number = 6): string {
  return digits === 8 ? '**** ****' : '*** ***';
}

function showToast(message: string): void {
  toastEl.textContent = message;
  toastEl.classList.remove('hidden');
  setTimeout(() => {
    toastEl.classList.add('hidden');
  }, 2200);
}

function showUnlockCard(
  method: 'biometrics' | 'pin' | 'password',
  bioAvailable: boolean,
  pinAvailable: boolean,
): void {
  cardUnlockBio.classList.toggle('hidden', method !== 'biometrics');
  formUnlockPin.classList.toggle('hidden', method !== 'pin');
  formUnlock.classList.toggle('hidden', method !== 'password');

  btnSwitchBio.classList.toggle('hidden', !bioAvailable || method === 'biometrics');
  btnSwitchPin.classList.toggle('hidden', !pinAvailable || method === 'pin');
  btnSwitchPwd.classList.toggle('hidden', method === 'password');

  unlockBioError.classList.add('hidden');
  unlockPinError.classList.add('hidden');
  unlockError.classList.add('hidden');

  if (method === 'pin') {
    unlockPin.value = '';
    unlockPin.focus();
  } else if (method === 'password') {
    unlockPassword.value = '';
    unlockPassword.focus();
  }
}

async function setupUnlockView(): Promise<void> {
  const bioAvailable = await hasBiometrics();
  const pinAvailable = await hasPin();
  const settings = await getSettings();

  let defaultMethod: 'biometrics' | 'pin' | 'password' = 'password';
  if (bioAvailable && settings.preferredUnlockMethod === 'biometrics') {
    defaultMethod = 'biometrics';
  } else if (pinAvailable && settings.preferredUnlockMethod === 'pin') {
    defaultMethod = 'pin';
  } else if (bioAvailable) {
    defaultMethod = 'biometrics';
  }

  showUnlockCard(defaultMethod, bioAvailable, pinAvailable);
}

function switchView(view: 'setup' | 'unlock' | 'main'): void {
  viewSetup.classList.toggle('hidden', view !== 'setup');
  viewUnlock.classList.toggle('hidden', view !== 'unlock');
  viewMain.classList.toggle('hidden', view !== 'main');
  if (view === 'unlock') {
    void setupUnlockView();
  }
}

async function detectActiveTab(): Promise<void> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id && tab.url) {
      currentTabId = tab.id;
      currentHostname = hostnameFromUrl(tab.url);
    }
  } catch {
    currentHostname = null;
    currentTabId = null;
  }
}

function updateTabSuggestion(): void {
  if (!currentHostname) {
    tabSuggestBanner.classList.add('hidden');
    return;
  }
  const matches = matchAccounts(accounts, currentHostname);
  activeMatchedAccount = pickAutofillAccount(matches);
  if (activeMatchedAccount) {
    suggestDomain.textContent = displayName(activeMatchedAccount);
    tabSuggestBanner.classList.remove('hidden');
  } else {
    tabSuggestBanner.classList.add('hidden');
  }
}

// -------------------------------------------------------------
// Rendering
// -------------------------------------------------------------

const RING_RADIUS = 9;
const RING_CIRCUMFERENCE = 2 * Math.PI * RING_RADIUS;

function createTimerSvg(): string {
  return `
    <div class="timer-container">
      <svg class="timer-svg" viewBox="0 0 24 24">
        <circle class="timer-track" cx="12" cy="12" r="${RING_RADIUS}"></circle>
        <circle class="timer-indicator" cx="12" cy="12" r="${RING_RADIUS}"
          stroke-dasharray="${RING_CIRCUMFERENCE}" stroke-dashoffset="0"></circle>
      </svg>
      <span class="timer-text"></span>
    </div>
  `;
}

async function renderAccounts(): Promise<void> {
  const filtered = accounts.filter((acc) => {
    if (!searchQuery) return true;
    const q = searchQuery.toLowerCase();
    const nameMatch = acc.issuer.toLowerCase().includes(q) || acc.label.toLowerCase().includes(q);
    const domainMatch = acc.domains.some((d) => d.toLowerCase().includes(q));
    return nameMatch || domainMatch;
  });

  // Sort: pinned accounts first
  const sorted = sortAccounts(filtered);

  if (sorted.length === 0) {
    accountsList.innerHTML = '';
    accountsEmpty.classList.remove('hidden');
    return;
  }
  accountsEmpty.classList.add('hidden');

  const fragment = document.createDocumentFragment();

  for (const account of sorted) {
    const card = document.createElement('div');
    card.className = `account-card ${account.pinned ? 'pinned' : ''}`;
    card.dataset.id = account.id;

    const initial = (account.issuer || account.label || '?').slice(0, 1).toUpperCase();
    const isHotp = account.type === 'hotp';
    const isRevealed = revealedAccountIds.has(account.id);
    const codePlaceholder = maskedCode(account.digits);

    card.innerHTML = `
      <div class="account-card-header">
        <div class="account-meta">
          <div class="account-avatar">${initial}</div>
          <div class="account-titles">
            <span class="account-issuer">
              ${escapeHtml(account.issuer || account.label)}
              ${account.pinned ? '<span class="pin-badge" title="Pinned account"><svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg></span>' : ''}
            </span>
            ${account.issuer && account.label ? `<span class="account-label">${escapeHtml(account.label)}</span>` : ''}
          </div>
        </div>
        <div class="account-actions-top">
          <button class="btn-icon btn-pin" title="${account.pinned ? 'Unpin code' : 'Pin code to top'}" aria-label="Pin">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="${account.pinned ? 'currentColor' : 'none'}" stroke="currentColor" stroke-width="2"><polygon points="12 2 15.09 8.26 22 9.27 17 14.14 18.18 21.02 12 17.77 5.82 21.02 7 14.14 2 9.27 8.91 8.26 12 2"/></svg>
          </button>
          <button class="btn-icon btn-edit" title="Edit account" aria-label="Edit">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 20h9"/><path d="M16.5 3.5a2.121 2.121 0 0 1 3 3L7 19l-4 1 1-4L16.5 3.5z"/></svg>
          </button>
          <button class="btn-icon btn-delete" title="Delete account" aria-label="Delete">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
          </button>
        </div>
      </div>
      <div class="account-code-row">
        <div class="account-code ${isRevealed ? '' : 'masked'}" title="Click to copy">${codePlaceholder}</div>
        <div class="account-controls">
          <button class="btn-icon btn-reveal" title="${isRevealed ? 'Hide code' : 'Reveal code'}" aria-label="${isRevealed ? 'Hide code' : 'Reveal code'}">
            ${isRevealed ? EYE_OFF_SVG : EYE_SVG}
          </button>
          ${isHotp ? '<button class="btn btn-sm btn-secondary btn-hotp">Next</button>' : createTimerSvg()}
          <button class="btn btn-sm btn-accent btn-fill" title="Fill into active webpage">Fill</button>
        </div>
      </div>
    `;

    fragment.appendChild(card);
  }

  accountsList.innerHTML = '';
  accountsList.appendChild(fragment);

  // Generate initial codes and start timer
  await updateAllCodes();
}

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

async function updateAllCodes(): Promise<void> {
  const cards = accountsList.querySelectorAll<HTMLElement>('.account-card');
  const now = Date.now();

  for (const card of cards) {
    const id = card.dataset.id;
    const account = accounts.find((a) => a.id === id);
    if (!account) continue;

    const codeEl = card.querySelector<HTMLElement>('.account-code');
    if (!codeEl) continue;

    const isRevealed = revealedAccountIds.has(account.id);
    const code = await generateCode(account, now);
    codeEl.dataset.code = code;
    codeEl.textContent = isRevealed ? formatCode(code) : maskedCode(account.digits);
    codeEl.classList.toggle('masked', !isRevealed);

    const revealBtn = card.querySelector<HTMLButtonElement>('.btn-reveal');
    if (revealBtn) {
      revealBtn.title = isRevealed ? 'Hide code' : 'Reveal code';
      revealBtn.setAttribute('aria-label', revealBtn.title);
      revealBtn.innerHTML = isRevealed ? EYE_OFF_SVG : EYE_SVG;
    }

    if (account.type === 'totp') {
      const remaining = secondsRemaining(account.period, now);
      const indicator = card.querySelector<SVGCircleElement>('.timer-indicator');
      const text = card.querySelector<HTMLElement>('.timer-text');

      if (indicator && text) {
        const fraction = remaining / account.period;
        const offset = RING_CIRCUMFERENCE * (1 - fraction);
        indicator.style.strokeDashoffset = String(offset);
        text.textContent = String(Math.ceil(remaining));

        indicator.classList.toggle('warning', remaining <= 7 && remaining > 3);
        indicator.classList.toggle('danger', remaining <= 3);
      }
    }
  }
}

function startCountdownLoop(): void {
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = window.setInterval(() => {
    updateAllCodes().catch(console.error);
  }, 1000);
}

// -------------------------------------------------------------
// Autofill Actions
// -------------------------------------------------------------

async function triggerAutofill(account: AccountEntry): Promise<void> {
  if (!currentTabId) {
    showToast('No active webpage found to fill.');
    return;
  }

  let code: string;
  if (account.type === 'hotp') {
    code = await consumeHotp(account.id);
    await refreshVault();
  } else {
    code = await generateCode(account);
  }

  const msg: FillCodeMessage = { type: 'FILL_CODE', code };
  try {
    await chrome.tabs.sendMessage(currentTabId, msg);
    showToast(`Filled ${displayName(account)}`);
  } catch {
    // If content script was not already loaded on this page, inject on demand
    try {
      await chrome.scripting.executeScript({
        target: { tabId: currentTabId },
        files: ['content/autofill.js'],
      });
      await chrome.tabs.sendMessage(currentTabId, msg);
      showToast(`Filled ${displayName(account)}`);
    } catch {
      showToast('Could not fill into this tab (check page permissions).');
    }
  }

  // Learn domain if enabled
  const settings = await getSettings();
  if (settings.learnDomains && currentHostname) {
    await rememberDomain(account.id, currentHostname);
  }
}

// -------------------------------------------------------------
// Vault Operations
// -------------------------------------------------------------

async function refreshVault(): Promise<void> {
  const vault = await loadVault();
  accounts = vault.accounts;
  updateTabSuggestion();
  await renderAccounts();
}

async function init(): Promise<void> {
  await detectActiveTab();

  const vaultExists = await hasVault();
  if (!vaultExists) {
    switchView('setup');
    return;
  }

  const unlocked = await isUnlocked();
  if (!unlocked) {
    switchView('unlock');
    return;
  }

  switchView('main');
  await refreshVault();
  startCountdownLoop();
}

// -------------------------------------------------------------
// Event Listeners
// -------------------------------------------------------------

// 1. Setup Form
formSetup.addEventListener('submit', async (e) => {
  e.preventDefault();
  setupError.classList.add('hidden');
  const p1 = setupPassword.value;
  const p2 = setupConfirm.value;
  if (p1 !== p2) {
    setupError.textContent = 'Passwords do not match.';
    setupError.classList.remove('hidden');
    return;
  }
  try {
    await createVault(p1);
    await init();
  } catch (err) {
    setupError.textContent = (err as Error).message;
    setupError.classList.remove('hidden');
  }
});

// 2. Unlock Forms & Methods
let navigatingAway = false;

btnUnlockBiometric.addEventListener('click', async () => {
  navigatingAway = true;
  unlockBioError.classList.add('hidden');
  try {
    await chrome.windows.create({
      url: chrome.runtime.getURL('unlock/unlock.html?method=biometrics'),
      type: 'popup',
      width: 380,
      height: 480,
      focused: true,
    });
  } catch {
    await chrome.tabs.create({
      url: chrome.runtime.getURL('unlock/unlock.html?method=biometrics'),
    });
  }
});

formUnlockPin.addEventListener('submit', async (e) => {
  e.preventDefault();
  unlockPinError.classList.add('hidden');
  const pin = unlockPin.value.trim();
  if (!pin) {
    return;
  }
  try {
    await unlockWithPin(pin);
    await init();
  } catch (err) {
    unlockPinError.textContent = (err as Error).message || 'Failed to unlock with PIN.';
    unlockPinError.classList.remove('hidden');
    unlockPin.select();
  }
});

btnSwitchBio.addEventListener('click', async () => {
  const [bioAvailable, pinAvailable] = await Promise.all([hasBiometrics(), hasPin()]);
  showUnlockCard('biometrics', bioAvailable, pinAvailable);
});

btnSwitchPin.addEventListener('click', async () => {
  const [bioAvailable, pinAvailable] = await Promise.all([hasBiometrics(), hasPin()]);
  showUnlockCard('pin', bioAvailable, pinAvailable);
});

btnSwitchPwd.addEventListener('click', async () => {
  const [bioAvailable, pinAvailable] = await Promise.all([hasBiometrics(), hasPin()]);
  showUnlockCard('password', bioAvailable, pinAvailable);
});

formUnlock.addEventListener('submit', async (e) => {
  e.preventDefault();
  unlockError.classList.add('hidden');
  try {
    await unlockVault(unlockPassword.value);
    await init();
  } catch (err) {
    if (err instanceof WrongPasswordError) {
      unlockError.textContent = 'Incorrect master password.';
    } else {
      unlockError.textContent = (err as Error).message || 'Failed to unlock vault.';
    }
    unlockError.classList.remove('hidden');
  }
});

unlockPassword.addEventListener('keyup', (e) => {
  if (e.getModifierState && e.getModifierState('CapsLock')) {
    unlockCaps.classList.remove('hidden');
  } else {
    unlockCaps.classList.add('hidden');
  }
});

// 3. Search Bar
searchInput.addEventListener('input', () => {
  searchQuery = searchInput.value.trim();
  btnSearchClear.classList.toggle('hidden', searchQuery.length === 0);
  renderAccounts().catch(console.error);
});

btnSearchClear.addEventListener('click', () => {
  searchInput.value = '';
  searchQuery = '';
  btnSearchClear.classList.add('hidden');
  renderAccounts().catch(console.error);
});

btnToggleAllVisibility.addEventListener('click', async () => {
  const allRevealed = accounts.length > 0 && accounts.every((a) => revealedAccountIds.has(a.id));
  if (allRevealed) {
    revealedAccountIds.clear();
    showToast('Masked all codes with *');
  } else {
    for (const a of accounts) {
      revealedAccountIds.add(a.id);
    }
    showToast('Revealed all codes.');
  }
  btnToggleAllVisibility.innerHTML = allRevealed ? EYE_SVG : EYE_OFF_SVG;
  btnToggleAllVisibility.title = allRevealed ? 'Reveal all codes' : 'Hide all codes';
  await updateAllCodes();
});

// 4. Header buttons
btnLockVault.addEventListener('click', async () => {
  await lockVault();
  if (timerInterval) clearInterval(timerInterval);
  switchView('unlock');
});

btnOpenOptions.addEventListener('click', () => {
  navigatingAway = true;
  chrome.runtime.openOptionsPage();
});

btnScanScreen.addEventListener('click', async () => {
  try {
    showToast('Scanning screen for QR...');
    const text = await scanVisibleTabForQr();
    if (!text) {
      showToast('No QR code found on the visible screen.');
      return;
    }
    const result = await importFromText(text);
    if (result.accounts.length === 0) {
      showToast('QR code did not contain valid 2FA details.');
      return;
    }
    await addAccounts(result.accounts);
    await refreshVault();
    showToast(`Added ${result.accounts.length} account(s) from screen.`);
  } catch (err) {
    showToast(`Scan error: ${(err as Error).message}`);
  }
});

btnUploadQrImage.addEventListener('click', () => {
  headerQrFileInput.value = '';
  headerQrFileInput.click();
});

headerQrFileInput.addEventListener('change', async () => {
  const file = headerQrFileInput.files?.[0];
  if (file) {
    await processDroppedFile(file);
  }
});

// Camera Scanner
const cameraScanner = new WebcamScanner();
let scannedQrTexts: Set<string> = new Set();
let batchImportedAccounts: ImportedAccount[] = [];

async function openCameraScanner(): Promise<void> {
  scannedQrTexts = new Set();
  batchImportedAccounts = [];
  cameraBatchBanner.classList.add('hidden');
  btnCameraFinish.classList.add('hidden');
  cameraStatus.textContent = 'Point camera at QR code (Google Authenticator, Aegis, 2FAS, etc.)';
  modalCamera.classList.remove('hidden');

  try {
    await cameraScanner.start(
      cameraVideo,
      async (text) => {
        if (scannedQrTexts.has(text)) {
          return;
        }
        scannedQrTexts.add(text);

        try {
          const result = await importFromText(text);
          if (result.accounts.length === 0) {
            cameraStatus.textContent = 'QR code detected, but contained no valid 2FA accounts.';
            return;
          }

          if (result.batch && result.batch.size > 1) {
            // Google Authenticator multi-part batch
            batchImportedAccounts.push(...result.accounts);
            cameraBatchCount.textContent = String(batchImportedAccounts.length);
            btnCameraFinish.classList.remove('hidden');
            cameraBatchBanner.textContent = `Scanned batch part ${result.batch.index + 1} of ${result.batch.size} (${batchImportedAccounts.length} accounts found). Point at next QR code.`;
            cameraBatchBanner.classList.remove('hidden');

            if (scannedQrTexts.size >= result.batch.size) {
              await finishCameraImport();
            }
          } else {
            // Single QR code (Google migration single, standard otpauth, Aegis, etc.)
            closeCameraScanner();
            await addAccounts(result.accounts);
            await refreshVault();
            showToast(`Imported ${result.accounts.length} account(s) via camera!`);
          }
        } catch (err) {
          cameraStatus.textContent = `Error: ${(err as Error).message}`;
        }
      },
      (err) => {
        cameraStatus.textContent = `Camera error: ${err.message}`;
      },
    );
  } catch (err) {
    cameraStatus.textContent = `Could not access camera: ${(err as Error).message}`;
  }
}

function closeCameraScanner(): void {
  cameraScanner.stop();
  modalCamera.classList.add('hidden');
}

async function finishCameraImport(): Promise<void> {
  const accountsToImport = [...batchImportedAccounts];
  closeCameraScanner();
  if (accountsToImport.length > 0) {
    await addAccounts(accountsToImport);
    await refreshVault();
    showToast(`Imported ${accountsToImport.length} account(s) from batch!`);
  }
}

btnScanCamera.addEventListener('click', () => {
  openCameraScanner().catch(console.error);
});

modalCameraClose.addEventListener('click', () => {
  closeCameraScanner();
});

btnCameraCancel.addEventListener('click', () => {
  closeCameraScanner();
});

btnCameraFinish.addEventListener('click', async () => {
  await finishCameraImport();
});

// Tab Suggest Autofill Banner
btnSuggestAutofill.addEventListener('click', () => {
  if (activeMatchedAccount) {
    triggerAutofill(activeMatchedAccount);
  }
});

// 5. Account List Delegated Events (Copy, Fill, Pin, Edit, Delete, HOTP)
accountsList.addEventListener('click', async (e) => {
  const target = e.target as HTMLElement;
  const card = target.closest<HTMLElement>('.account-card');
  if (!card) return;
  const id = card.dataset.id;
  const account = accounts.find((a) => a.id === id);
  if (!account) return;

  // Pin Toggle
  if (target.closest('.btn-pin')) {
    e.stopPropagation();
    const isPinned = await togglePinAccount(account.id);
    await refreshVault();
    showToast(isPinned ? `Pinned ${displayName(account)}` : `Unpinned ${displayName(account)}`);
    return;
  }

  // Reveal / Hide Button
  if (target.closest('.btn-reveal')) {
    e.stopPropagation();
    if (revealedAccountIds.has(account.id)) {
      revealedAccountIds.delete(account.id);
    } else {
      revealedAccountIds.add(account.id);
    }
    await updateAllCodes();
    return;
  }

  // Edit Button
  if (target.closest('.btn-edit')) {
    e.stopPropagation();
    openEditModal(account);
    return;
  }

  // Delete Button
  if (target.closest('.btn-delete')) {
    e.stopPropagation();
    if (confirm(`Delete 2FA account for "${displayName(account)}"? This cannot be undone.`)) {
      await deleteAccount(account.id);
      await refreshVault();
      showToast(`Deleted ${displayName(account)}`);
    }
    return;
  }

  // Fill Button
  if (target.closest('.btn-fill')) {
    e.stopPropagation();
    await triggerAutofill(account);
    return;
  }

  // HOTP Next Button
  if (target.closest('.btn-hotp')) {
    e.stopPropagation();
    const code = await consumeHotp(account.id);
    const isRevealed = revealedAccountIds.has(account.id);
    const codeEl = card.querySelector<HTMLElement>('.account-code');
    if (codeEl) {
      codeEl.dataset.code = code;
      codeEl.textContent = isRevealed ? formatCode(code) : maskedCode(account.digits);
      codeEl.classList.toggle('masked', !isRevealed);
    }
    await navigator.clipboard.writeText(code);
    showToast(`HOTP copied: ${code}`);
    await refreshVault();
    return;
  }

  // Clicking the code element copies to clipboard
  if (target.closest('.account-code')) {
    e.stopPropagation();
    const code = await generateCode(account);
    await navigator.clipboard.writeText(code);
    showToast(`Copied ${formatCode(code)} to clipboard!`);
    return;
  }

  // Clicking anywhere else on the card copies to clipboard
  const code = await generateCode(account);
  await navigator.clipboard.writeText(code);
  showToast(`Copied ${formatCode(code)} to clipboard!`);
});

// 6. Add / Edit Account Modal
btnAddAccount.addEventListener('click', () => {
  openAddModal();
});

modalClose.addEventListener('click', () => {
  modalAccount.classList.add('hidden');
});

btnCancelAccount.addEventListener('click', () => {
  modalAccount.classList.add('hidden');
});

// Type toggle for Period vs Counter fields
accType.addEventListener('change', () => {
  const isHotp = accType.value === 'hotp';
  groupPeriod.classList.toggle('hidden', isHotp);
  groupCounter.classList.toggle('hidden', !isHotp);
});

// Tabs inside Add modal
addModalTabs.addEventListener('click', (e) => {
  const btn = (e.target as HTMLElement).closest<HTMLButtonElement>('.tab-btn');
  if (!btn) return;
  const tab = btn.dataset.tab;
  addModalTabs.querySelectorAll('.tab-btn').forEach((b) => b.classList.remove('active'));
  btn.classList.add('active');
  modalAccount.querySelectorAll<HTMLElement>('.tab-content').forEach((c) => {
    c.classList.toggle('active', c.dataset.content === tab);
  });
});

function openAddModal(): void {
  modalTitle.textContent = 'Add 2FA Account';
  addModalTabs.classList.remove('hidden');
  accountIdInput.value = '';
  formAccount.reset();
  accType.value = 'totp';
  accAlgo.value = DEFAULT_ALGORITHM;
  accDigits.value = String(DEFAULT_DIGITS);
  accPeriod.value = String(DEFAULT_PERIOD);
  accCounter.value = '0';
  groupPeriod.classList.remove('hidden');
  groupCounter.classList.add('hidden');
  accountError.classList.add('hidden');
  qrDropStatus.classList.add('hidden');

  // Activate first tab
  addModalTabs.querySelector<HTMLButtonElement>('[data-tab="manual"]')?.click();
  modalAccount.classList.remove('hidden');
  accIssuer.focus();
}

function openEditModal(account: AccountEntry): void {
  modalTitle.textContent = 'Edit 2FA Account';
  addModalTabs.classList.add('hidden'); // No QR drop tab in edit mode
  accountIdInput.value = account.id;
  accIssuer.value = account.issuer;
  accLabel.value = account.label;
  accSecret.value = account.secret;
  accType.value = account.type;
  accAlgo.value = account.algorithm;
  accDigits.value = String(account.digits);
  accPeriod.value = String(account.period);
  accCounter.value = String(account.counter);
  accDomains.value = account.domains.join(', ');
  accPinned.checked = Boolean(account.pinned);

  const isHotp = account.type === 'hotp';
  groupPeriod.classList.toggle('hidden', isHotp);
  groupCounter.classList.toggle('hidden', !isHotp);
  accountError.classList.add('hidden');

  modalAccount.querySelector<HTMLButtonElement>('[data-tab="manual"]')?.click();
  modalAccount.classList.remove('hidden');
  accIssuer.focus();
}

formAccount.addEventListener('submit', async (e) => {
  e.preventDefault();
  accountError.classList.add('hidden');

  const id = accountIdInput.value;
  const rawDomains = accDomains.value
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);

  const candidate = {
    issuer: accIssuer.value.trim(),
    label: accLabel.value.trim(),
    secret: accSecret.value.trim(),
    type: accType.value as 'totp' | 'hotp',
    algorithm: accAlgo.value as OtpParams['algorithm'],
    digits: Number(accDigits.value) as 6 | 8,
    period: Number(accPeriod.value),
    counter: Number(accCounter.value),
    domains: rawDomains,
    pinned: accPinned.checked,
  };

  const validation = validateImported(candidate);
  if (typeof validation === 'string') {
    accountError.textContent = validation;
    accountError.classList.remove('hidden');
    return;
  }

  try {
    if (id) {
      await editAccount(id, candidate);
      showToast(`Updated ${displayName(candidate)}`);
    } else {
      await addAccounts([validation]);
      showToast(`Added ${displayName(candidate)}`);
    }
    modalAccount.classList.add('hidden');
    await refreshVault();
  } catch (err) {
    accountError.textContent = (err as Error).message;
    accountError.classList.remove('hidden');
  }
});

// Dropzone QR code parsing
qrDropzone.addEventListener('click', () => {
  qrFileInput.click();
});

qrFileInput.addEventListener('change', async () => {
  const file = qrFileInput.files?.[0];
  if (file) {
    await processDroppedFile(file);
  }
});

qrDropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  qrDropzone.classList.add('dragover');
});

qrDropzone.addEventListener('dragleave', () => {
  qrDropzone.classList.remove('dragover');
});

qrDropzone.addEventListener('drop', async (e) => {
  e.preventDefault();
  qrDropzone.classList.remove('dragover');
  const file = e.dataTransfer?.files[0];
  if (file) {
    await processDroppedFile(file);
  }
});

async function processDroppedFile(file: File): Promise<void> {
  qrDropStatus.textContent = 'Processing image...';
  qrDropStatus.classList.remove('hidden');
  try {
    showToast('Decoding QR image...');
    const result = await importFromImage(file);
    if (result.accounts.length === 0) {
      qrDropStatus.textContent = 'No valid 2FA credentials found in that image.';
      showToast('No valid 2FA credentials found in that image.');
      return;
    }
    await addAccounts(result.accounts);
    await refreshVault();
    modalAccount.classList.add('hidden');
    showToast(`Imported ${result.accounts.length} account(s)!`);
  } catch (err) {
    const errorMsg = (err as Error).message;
    qrDropStatus.textContent = `Error: ${errorMsg}`;
    showToast(`Import error: ${errorMsg}`);
  }
}

// Support drag-and-drop anywhere onto popup main window
window.addEventListener('dragover', (e) => {
  e.preventDefault();
});

viewMain.addEventListener('dragover', (e) => {
  e.preventDefault();
  viewMain.classList.add('dragover');
});

viewMain.addEventListener('dragleave', (e) => {
  if (e.relatedTarget === null || !viewMain.contains(e.relatedTarget as Node)) {
    viewMain.classList.remove('dragover');
  }
});

viewMain.addEventListener('drop', async (e) => {
  e.preventDefault();
  viewMain.classList.remove('dragover');
  const file = e.dataTransfer?.files[0];
  if (file && (file.type.startsWith('image/') || /\.(png|jpe?g|gif|webp|bmp)$/i.test(file.name))) {
    await processDroppedFile(file);
  }
});

// Support pasting a screenshot or QR image from clipboard (Cmd+V / Ctrl+V)
document.addEventListener('paste', async (e) => {
  const items = e.clipboardData?.items;
  if (!items) return;
  for (const item of items) {
    if (item.type.startsWith('image/')) {
      const file = item.getAsFile();
      if (file) {
        await processDroppedFile(file);
        break;
      }
    }
  }
});

// Automatically lock on popup close if the setting is enabled
window.addEventListener('pagehide', () => {
  if (!navigatingAway) {
    chrome.runtime.sendMessage({ type: 'POPUP_CLOSED' });
  }
});

// Sync UI state if session changes in another window (e.g. biometric unlock window)
chrome.storage.onChanged.addListener(async (_changes, area) => {
  if (area === 'session') {
    const unlocked = await isUnlocked();
    if (unlocked) {
      await init();
    } else if (await hasVault()) {
      switchView('unlock');
    }
  }
});

// Start application
init().catch(console.error);
