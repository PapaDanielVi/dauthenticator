/**
 * Background Service Worker for DAuthenticator.
 *
 * Responsibilities:
 * - Hardens chrome.storage.local and chrome.storage.session access levels on startup.
 * - Manages auto-lock timer and OS lock listeners.
 * - Handles the keyboard shortcut (Command/Ctrl+Shift+L) to find matching OTP and autofill.
 * - Executes autofill script injection on demand.
 */
import { hardenStorageAccess, isUnlocked, loadVault, lockVault, getUnlockedAt, hasVault } from '../crypto/vault';
import { generateCode } from '../crypto/totp';
import { hostnameFromUrl, matchAccounts, pickAutofillAccount } from '../shared/match';
import { getSettings } from '../shared/settings';
import type { FillCodeMessage } from '../shared/messages';

const AUTO_LOCK_ALARM = 'dauth.autoLockCheck';

async function setupStorageSecurity(): Promise<void> {
  try {
    await hardenStorageAccess();
  } catch (err) {
    console.error('Failed to set storage access level:', err);
  }
}

async function checkAutoLock(): Promise<void> {
  const unlocked = await isUnlocked();
  if (!unlocked) {
    return;
  }
  const settings = await getSettings();
  if (settings.autoLockMinutes <= 0) {
    return;
  }
  const unlockedAt = await getUnlockedAt();
  if (!unlockedAt) {
    return;
  }
  const elapsedMs = Date.now() - unlockedAt;
  const timeoutMs = settings.autoLockMinutes * 60 * 1000;
  if (elapsedMs >= timeoutMs) {
    await lockVault();
    updateBadge();
  }
}

async function updateBadge(): Promise<void> {
  try {
    const vaultExists = await hasVault();
    if (!vaultExists) {
      await chrome.action.setBadgeText({ text: '' });
      return;
    }
    const unlocked = await isUnlocked();
    if (unlocked) {
      await chrome.action.setBadgeText({ text: '' });
    } else {
      await chrome.action.setBadgeText({ text: 'LOCK' });
      await chrome.action.setBadgeBackgroundColor({ color: '#64748b' });
    }
  } catch {
    // Service worker may be terminating or chrome API not ready
  }
}

async function autofillActiveTab(): Promise<void> {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id || !tab.url) {
    return;
  }

  const hostname = hostnameFromUrl(tab.url);
  if (!hostname) {
    return;
  }

  const unlocked = await isUnlocked();
  if (!unlocked) {
    // Open the popup if supported so the user can unlock
    try {
      if (chrome.action.openPopup) {
        await chrome.action.openPopup();
      }
    } catch {
      // Ignored if popup cannot be opened programmatically
    }
    return;
  }

  const vault = await loadVault();
  const matches = matchAccounts(vault.accounts, hostname);
  const target = pickAutofillAccount(matches);
  if (!target) {
    // Multiple matches or no match: open popup so user can choose
    try {
      if (chrome.action.openPopup) {
        await chrome.action.openPopup();
      }
    } catch {
      // Ignored
    }
    return;
  }

  const code = await generateCode(target);

  // Send message to tab; if tab has not injected script yet, inject it first
  try {
    const msg: FillCodeMessage = { type: 'FILL_CODE', code };
    await chrome.tabs.sendMessage(tab.id, msg);
  } catch {
    // Inject script and retry
    try {
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        files: ['content/autofill.js'],
      });
      const msg: FillCodeMessage = { type: 'FILL_CODE', code };
      await chrome.tabs.sendMessage(tab.id, msg);
    } catch (err) {
      console.error('Failed to inject or message autofill script:', err);
    }
  }
}

// Hardening on service worker initialization
setupStorageSecurity().catch((err) => {
  console.error('Failed to set storage access level during initialization:', err);
});

function setupContextMenu(): void {
  try {
    chrome.contextMenus.create({
      id: 'lock-vault-action',
      title: 'Lock DAuthenticator Vault',
      contexts: ['action'],
    });
  } catch {
    // Menu item may already exist
  }
}

// Lifecycle events
chrome.runtime.onInstalled.addListener(async () => {
  await setupStorageSecurity();
  await chrome.alarms.create(AUTO_LOCK_ALARM, { periodInMinutes: 1 });
  await updateBadge();
  setupContextMenu();
});

chrome.runtime.onStartup.addListener(async () => {
  await setupStorageSecurity();
  await updateBadge();
  setupContextMenu();
});

// Context menu listener
chrome.contextMenus.onClicked.addListener(async (info) => {
  if (info.menuItemId === 'lock-vault-action') {
    await lockVault();
    await updateBadge();
  }
});

// Periodic alarm check for inactivity timeout
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === AUTO_LOCK_ALARM) {
    await checkAutoLock();
  }
});

// System idle / lock detection
chrome.idle.onStateChanged.addListener(async (state) => {
  if (state === 'locked') {
    const settings = await getSettings();
    if (settings.lockOnSystemLock) {
      await lockVault();
      await updateBadge();
    }
  }
});

// Lock when browser window loses focus (if enabled)
chrome.windows.onFocusChanged.addListener(async (windowId) => {
  if (windowId === chrome.windows.WINDOW_ID_NONE) {
    const settings = await getSettings();
    if (settings.lockOnWindowBlur) {
      await lockVault();
      await updateBadge();
    }
  }
});

// Keyboard command shortcut listener
chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'fill-otp') {
    await autofillActiveTab();
  } else if (command === 'lock-vault') {
    await lockVault();
    await updateBadge();
  }
});

// Message listener for explicit lock actions or popup events
chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message?.type === 'LOCK_VAULT') {
    void lockVault().then(() => updateBadge()).then(() => sendResponse({ success: true }));
    return true;
  }
  if (message?.type === 'POPUP_CLOSED') {
    void (async () => {
      const settings = await getSettings();
      if (settings.lockOnPopupClose) {
        await lockVault();
        await updateBadge();
      }
    })();
    return false;
  }
  return false;
});

// Broadcast storage changes to update badge
chrome.storage.onChanged.addListener((_changes, area) => {
  if (area === 'session' || area === 'local') {
    updateBadge();
  }
});

export {};
