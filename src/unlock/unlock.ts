/**
 * Standalone Unlock Controller for DAuthenticator.
 *
 * Runs inside a dedicated window/tab to prevent Chrome from closing the UI
 * when OS biometric prompts (Touch ID / Windows Hello) gain focus.
 */
import { hasVault, isUnlocked, unlockVault } from '../crypto/vault';
import { hasBiometrics, unlockWithBiometrics } from '../crypto/biometrics';
import { hasPin, unlockWithPin } from '../crypto/pin';
import { getSettings } from '../shared/settings';

const sectionBio = document.getElementById('section-biometric') as HTMLElement;
const sectionPin = document.getElementById('section-pin') as HTMLElement;
const sectionPwd = document.getElementById('section-password') as HTMLElement;

const btnTriggerBio = document.getElementById('btn-trigger-bio') as HTMLButtonElement;
const bioStatus = document.getElementById('bio-status') as HTMLElement;
const bioError = document.getElementById('bio-error') as HTMLElement;

const formPin = document.getElementById('form-pin') as HTMLFormElement;
const inputPin = document.getElementById('input-pin') as HTMLInputElement;
const pinError = document.getElementById('pin-error') as HTMLElement;

const formPwd = document.getElementById('form-password') as HTMLFormElement;
const inputPwd = document.getElementById('input-password') as HTMLInputElement;
const pwdError = document.getElementById('password-error') as HTMLElement;

const switchToBio = document.getElementById('switch-to-bio') as HTMLButtonElement;
const switchToPin = document.getElementById('switch-to-pin') as HTMLButtonElement;
const switchToPwd = document.getElementById('switch-to-pwd') as HTMLButtonElement;
const btnCancel = document.getElementById('btn-cancel-window') as HTMLButtonElement;

type UnlockMethod = 'biometrics' | 'pin' | 'password';

function showSection(method: UnlockMethod): void {
  sectionBio.classList.toggle('hidden', method !== 'biometrics');
  sectionPin.classList.toggle('hidden', method !== 'pin');
  sectionPwd.classList.toggle('hidden', method !== 'password');

  bioError.classList.add('hidden');
  pinError.classList.add('hidden');
  pwdError.classList.add('hidden');

  if (method === 'pin') {
    inputPin.value = '';
    inputPin.focus();
  } else if (method === 'password') {
    inputPwd.value = '';
    inputPwd.focus();
  }
}

async function triggerBiometric(): Promise<void> {
  bioError.classList.add('hidden');
  bioStatus.textContent = 'Touch your fingerprint sensor or activate your passkey...';
  btnTriggerBio.disabled = true;

  try {
    await unlockWithBiometrics();
    window.close();
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Biometric verification failed.';
    bioError.textContent = message;
    bioError.classList.remove('hidden');
    bioStatus.textContent = 'Authentication was not completed.';
    btnTriggerBio.disabled = false;
  }
}

async function init(): Promise<void> {
  if (!(await hasVault())) {
    window.close();
    return;
  }

  if (await isUnlocked()) {
    window.close();
    return;
  }

  const bioConfigured = await hasBiometrics();
  const pinConfigured = await hasPin();
  const settings = await getSettings();

  switchToBio.classList.toggle('hidden', !bioConfigured);
  switchToPin.classList.toggle('hidden', !pinConfigured);

  const urlParams = new URLSearchParams(window.location.search);
  const methodParam = urlParams.get('method') as UnlockMethod | null;

  let activeMethod: UnlockMethod = 'password';

  if (methodParam === 'biometrics' && bioConfigured) {
    activeMethod = 'biometrics';
  } else if (methodParam === 'pin' && pinConfigured) {
    activeMethod = 'pin';
  } else if (methodParam === 'password') {
    activeMethod = 'password';
  } else if (bioConfigured && settings.preferredUnlockMethod === 'biometrics') {
    activeMethod = 'biometrics';
  } else if (pinConfigured && settings.preferredUnlockMethod === 'pin') {
    activeMethod = 'pin';
  } else if (bioConfigured) {
    activeMethod = 'biometrics';
  }

  showSection(activeMethod);

  // If opening directly to biometrics, trigger the biometric prompt after a brief render delay
  if (activeMethod === 'biometrics') {
    setTimeout(() => {
      void triggerBiometric();
    }, 200);
  }
}

// Event Listeners
btnTriggerBio.addEventListener('click', () => {
  void triggerBiometric();
});

formPin.addEventListener('submit', async (e) => {
  e.preventDefault();
  pinError.classList.add('hidden');
  const pin = inputPin.value.trim();
  if (!pin) {
    return;
  }

  try {
    await unlockWithPin(pin);
    window.close();
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to unlock with PIN.';
    pinError.textContent = message;
    pinError.classList.remove('hidden');
    inputPin.select();
  }
});

formPwd.addEventListener('submit', async (e) => {
  e.preventDefault();
  pwdError.classList.add('hidden');
  const password = inputPwd.value;
  if (!password) {
    return;
  }

  try {
    await unlockVault(password);
    window.close();
  } catch (err) {
    const message = err instanceof Error ? err.message : 'Failed to unlock vault.';
    pwdError.textContent = message;
    pwdError.classList.remove('hidden');
    inputPwd.select();
  }
});

switchToBio.addEventListener('click', () => {
  showSection('biometrics');
  void triggerBiometric();
});

switchToPin.addEventListener('click', () => {
  showSection('pin');
});

switchToPwd.addEventListener('click', () => {
  showSection('password');
});

btnCancel.addEventListener('click', () => {
  window.close();
});

void init();
