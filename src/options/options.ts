/**
 * Options & Settings Controller for DAuthenticator.
 */
import {
  changePassword,
  destroyVault,
} from '../crypto/vault';
import { getSettings, updateSettings } from '../shared/settings';
import { addAccounts } from '../shared/vaultOps';
import { clearSync, getSyncStatus, mergeFromSync, pushVaultToSync } from '../shared/sync';
import { exportEncryptedBackup, exportPlainJsonBackup, exportPlainUriList } from '../shared/export';
import { importFromFile, importFromText, SOURCE_LABELS, type ImportResult } from '../importers';
import { PasswordRequiredError } from '../shared/errors';
import type { ImportedAccount } from '../shared/types';

// DOM Elements
const navItems = document.querySelectorAll<HTMLButtonElement>('.nav-item');
const tabPanes = document.querySelectorAll<HTMLElement>('.tab-pane');

// Import elements
const importDropzone = document.getElementById('import-dropzone') as HTMLElement;
const importFileInput = document.getElementById('import-file-input') as HTMLInputElement;
const importPasteArea = document.getElementById('import-paste-area') as HTMLTextAreaElement;
const btnImportPaste = document.getElementById('btn-import-paste') as HTMLButtonElement;
const importPreviewCard = document.getElementById('import-preview-card') as HTMLElement;
const previewSourceTitle = document.getElementById('preview-source-title') as HTMLElement;
const previewCount = document.getElementById('preview-count') as HTMLElement;
const btnConfirmImport = document.getElementById('btn-confirm-import') as HTMLButtonElement;
const previewWarnings = document.getElementById('preview-warnings') as HTMLElement;
const previewTableBody = document.getElementById('preview-table-body') as HTMLElement;

// Backup elements
const btnExportEnc = document.getElementById('btn-export-enc') as HTMLButtonElement;
const btnExportEncJson = document.getElementById('btn-export-enc-json') as HTMLButtonElement;
const exportPasswordConfirm = document.getElementById('export-password-confirm') as HTMLInputElement;
const exportError = document.getElementById('export-error') as HTMLElement;
const btnExportJson = document.getElementById('btn-export-json') as HTMLButtonElement;
const btnExportUris = document.getElementById('btn-export-uris') as HTMLButtonElement;

// Sync elements
const syncStatusText = document.getElementById('sync-status-text') as HTMLElement;
const syncLastTime = document.getElementById('sync-last-time') as HTMLElement;
const syncQuotaUsage = document.getElementById('sync-quota-usage') as HTMLElement;
const settingAutoSync = document.getElementById('setting-auto-sync') as HTMLInputElement;
const btnSyncPush = document.getElementById('btn-sync-push') as HTMLButtonElement;
const btnSyncMerge = document.getElementById('btn-sync-merge') as HTMLButtonElement;
const syncAlert = document.getElementById('sync-alert') as HTMLElement;

// Security elements
const formChangePassword = document.getElementById('form-change-password') as HTMLFormElement;
const pwdCurrent = document.getElementById('pwd-current') as HTMLInputElement;
const pwdNew = document.getElementById('pwd-new') as HTMLInputElement;
const pwdConfirm = document.getElementById('pwd-confirm') as HTMLInputElement;
const pwdError = document.getElementById('pwd-error') as HTMLElement;
const pwdSuccess = document.getElementById('pwd-success') as HTMLElement;

const settingAutolock = document.getElementById('setting-autolock') as HTMLSelectElement;
const settingLockSystem = document.getElementById('setting-lock-system') as HTMLInputElement;
const settingLearnDomains = document.getElementById('setting-learn-domains') as HTMLInputElement;
const btnSavePrefs = document.getElementById('btn-save-prefs') as HTMLButtonElement;
const btnDestroyVault = document.getElementById('btn-destroy-vault') as HTMLButtonElement;

// Password modal
const modalPassword = document.getElementById('modal-password') as HTMLElement;
const modalPwdTitle = document.getElementById('modal-pwd-title') as HTMLElement;
const modalPwdDesc = document.getElementById('modal-pwd-desc') as HTMLElement;
const formDecryptBackup = document.getElementById('form-decrypt-backup') as HTMLFormElement;
const backupPwdInput = document.getElementById('backup-pwd-input') as HTMLInputElement;
const backupPwdError = document.getElementById('backup-pwd-error') as HTMLElement;
const btnCancelBackupPwd = document.getElementById('btn-cancel-backup-pwd') as HTMLButtonElement;
const modalPwdClose = document.getElementById('modal-pwd-close') as HTMLButtonElement;

const toastEl = document.getElementById('toast') as HTMLElement;

// State
let stagedAccounts: ImportedAccount[] = [];
let pendingFileToImport: File | null = null;
let pendingTextToImport: string | null = null;
let pendingSyncPasswordResolve: ((pwd: string) => void) | null = null;

function showToast(message: string): void {
  toastEl.textContent = message;
  toastEl.classList.remove('hidden');
  setTimeout(() => {
    toastEl.classList.add('hidden');
  }, 2500);
}

// Tab navigation
navItems.forEach((btn) => {
  btn.addEventListener('click', () => {
    const tab = btn.dataset.tab;
    navItems.forEach((b) => b.classList.remove('active'));
    tabPanes.forEach((p) => p.classList.remove('active'));
    btn.classList.add('active');
    const target = document.getElementById(`tab-${tab}`);
    if (target) target.classList.add('active');
  });
});

// -------------------------------------------------------------
// Universal Importer
// -------------------------------------------------------------

importDropzone.addEventListener('click', () => {
  importFileInput.click();
});

importDropzone.addEventListener('dragover', (e) => {
  e.preventDefault();
  importDropzone.classList.add('dragover');
});

importDropzone.addEventListener('dragleave', () => {
  importDropzone.classList.remove('dragover');
});

importDropzone.addEventListener('drop', async (e) => {
  e.preventDefault();
  importDropzone.classList.remove('dragover');
  const file = e.dataTransfer?.files[0];
  if (file) {
    await handleImportFile(file);
  }
});

importFileInput.addEventListener('change', async () => {
  const file = importFileInput.files?.[0];
  if (file) {
    await handleImportFile(file);
  }
});

btnImportPaste.addEventListener('click', async () => {
  const text = importPasteArea.value.trim();
  if (!text) {
    showToast('Paste data into the text box first.');
    return;
  }
  await handleImportText(text);
});

async function handleImportFile(file: File, password?: string): Promise<void> {
  pendingFileToImport = file;
  pendingTextToImport = null;
  try {
    const result = await importFromFile(file, { password });
    displayImportPreview(result);
  } catch (err) {
    if (err instanceof PasswordRequiredError) {
      promptPassword(err.kind, err.wrongPassword);
      return;
    }
    showToast(`Import error: ${(err as Error).message}`);
  }
}

async function handleImportText(text: string, password?: string): Promise<void> {
  pendingTextToImport = text;
  pendingFileToImport = null;
  try {
    const result = await importFromText(text, { password });
    displayImportPreview(result);
  } catch (err) {
    if (err instanceof PasswordRequiredError) {
      promptPassword(err.kind, err.wrongPassword);
      return;
    }
    showToast(`Import error: ${(err as Error).message}`);
  }
}

function promptPassword(kind: string, isWrong: boolean): void {
  modalPwdTitle.textContent = `${kind.toUpperCase()} Password Required`;
  modalPwdDesc.textContent = isWrong
    ? 'Incorrect password. Please enter the correct password for this backup:'
    : `This ${kind} backup is encrypted. Enter its password to decrypt:`;
  backupPwdInput.value = '';
  backupPwdError.classList.add('hidden');
  modalPassword.classList.remove('hidden');
  backupPwdInput.focus();
}

formDecryptBackup.addEventListener('submit', async (e) => {
  e.preventDefault();
  const password = backupPwdInput.value;
  modalPassword.classList.add('hidden');

  if (pendingSyncPasswordResolve) {
    pendingSyncPasswordResolve(password);
    pendingSyncPasswordResolve = null;
    return;
  }

  if (pendingFileToImport) {
    await handleImportFile(pendingFileToImport, password);
  } else if (pendingTextToImport) {
    await handleImportText(pendingTextToImport, password);
  }
});

btnCancelBackupPwd.addEventListener('click', () => {
  modalPassword.classList.add('hidden');
  pendingFileToImport = null;
  pendingTextToImport = null;
  pendingSyncPasswordResolve = null;
});

modalPwdClose.addEventListener('click', () => {
  modalPassword.classList.add('hidden');
  pendingFileToImport = null;
  pendingTextToImport = null;
  pendingSyncPasswordResolve = null;
});

function displayImportPreview(result: ImportResult): void {
  stagedAccounts = result.accounts;
  const label = SOURCE_LABELS[result.source] ?? result.source;
  previewSourceTitle.textContent = `Found ${result.accounts.length} account(s) from ${label}`;
  previewCount.textContent = `Ready to merge into your vault. Duplicates will be safely ignored.`;

  if (result.warnings.length > 0) {
    previewWarnings.innerHTML = `<strong>Skipped items:</strong><br>${result.warnings.map(escapeHtml).join('<br>')}`;
    previewWarnings.classList.remove('hidden');
  } else {
    previewWarnings.classList.add('hidden');
  }

  previewTableBody.innerHTML = '';
  result.accounts.forEach((acc) => {
    const row = document.createElement('tr');
    row.innerHTML = `
      <td>${acc.type.toUpperCase()}</td>
      <td><strong>${escapeHtml(acc.issuer || '-')}</strong></td>
      <td>${escapeHtml(acc.label || '-')}</td>
      <td>${acc.algorithm}</td>
      <td>${acc.digits}</td>
    `;
    previewTableBody.appendChild(row);
  });

  importPreviewCard.classList.remove('hidden');
  importPreviewCard.scrollIntoView({ behavior: 'smooth' });
}

btnConfirmImport.addEventListener('click', async () => {
  if (stagedAccounts.length === 0) {
    showToast('No accounts to import.');
    return;
  }
  try {
    const merge = await addAccounts(stagedAccounts);
    showToast(`Successfully added ${merge.added.length} accounts (${merge.duplicates} duplicates ignored).`);
    importPreviewCard.classList.add('hidden');
    stagedAccounts = [];
    importPasteArea.value = '';
    importFileInput.value = '';
  } catch (err) {
    showToast(`Error adding accounts: ${(err as Error).message}`);
  }
});

function escapeHtml(text: string): string {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// -------------------------------------------------------------
// Backup & Export
// -------------------------------------------------------------

btnExportEnc.addEventListener('click', async () => {
  try {
    await exportEncryptedBackup('enc');
    showToast('Encrypted .enc backup exported.');
  } catch (err) {
    showToast(`Export error: ${(err as Error).message}`);
  }
});

btnExportEncJson.addEventListener('click', async () => {
  try {
    await exportEncryptedBackup('json');
    showToast('Encrypted .json backup exported.');
  } catch (err) {
    showToast(`Export error: ${(err as Error).message}`);
  }
});

btnExportJson.addEventListener('click', async () => {
  exportError.classList.add('hidden');
  const pwd = exportPasswordConfirm.value;
  if (!pwd) {
    exportError.textContent = 'Enter your master password to authorize plaintext export.';
    exportError.classList.remove('hidden');
    return;
  }
  try {
    await exportPlainJsonBackup(pwd);
    exportPasswordConfirm.value = '';
    showToast('Plaintext JSON exported.');
  } catch (err) {
    exportError.textContent = (err as Error).message;
    exportError.classList.remove('hidden');
  }
});

btnExportUris.addEventListener('click', async () => {
  exportError.classList.add('hidden');
  const pwd = exportPasswordConfirm.value;
  if (!pwd) {
    exportError.textContent = 'Enter your master password to authorize plaintext export.';
    exportError.classList.remove('hidden');
    return;
  }
  try {
    await exportPlainUriList(pwd);
    exportPasswordConfirm.value = '';
    showToast('otpauth:// URI list exported.');
  } catch (err) {
    exportError.textContent = (err as Error).message;
    exportError.classList.remove('hidden');
  }
});

// -------------------------------------------------------------
// Chrome Storage Sync
// -------------------------------------------------------------

async function refreshSyncInfo(): Promise<void> {
  try {
    const status = await getSyncStatus();
    const settings = await getSettings();

    settingAutoSync.checked = settings.autoSync;

    if (status.meta) {
      syncStatusText.textContent = 'Active Backup Available';
      syncLastTime.textContent = new Date(status.meta.updatedAt).toLocaleString();
      syncQuotaUsage.textContent = `${Math.round(status.bytesInUse / 1024)} KB / ${Math.round(status.quotaBytes / 1024)} KB`;
    } else {
      syncStatusText.textContent = 'No Backup in Sync';
      syncLastTime.textContent = 'Never';
      syncQuotaUsage.textContent = `0 KB / ${Math.round(status.quotaBytes / 1024)} KB`;
    }
  } catch {
    syncStatusText.textContent = 'Sync unavailable';
  }
}

settingAutoSync.addEventListener('change', async () => {
  await updateSettings({ autoSync: settingAutoSync.checked });
  showToast(settingAutoSync.checked ? 'Auto-sync enabled.' : 'Auto-sync disabled.');
});

btnSyncPush.addEventListener('click', async () => {
  syncAlert.classList.add('hidden');
  try {
    const meta = await pushVaultToSync();
    await refreshSyncInfo();
    syncAlert.textContent = `Pushed ${meta.chunks} encrypted chunk(s) to Chrome Sync.`;
    syncAlert.classList.remove('hidden');
  } catch (err) {
    syncAlert.textContent = `Sync push error: ${(err as Error).message}`;
    syncAlert.classList.remove('hidden');
  }
});

btnSyncMerge.addEventListener('click', async () => {
  syncAlert.classList.add('hidden');
  try {
    const result = await mergeFromSync();
    syncAlert.textContent = `Restored! Added ${result.added.length} accounts (${result.duplicates} already present).`;
    syncAlert.classList.remove('hidden');
    await refreshSyncInfo();
  } catch (err) {
    if (err instanceof PasswordRequiredError) {
      promptPassword('sync', err.wrongPassword);
      pendingSyncPasswordResolve = async (pwd) => {
        try {
          const res = await mergeFromSync(pwd);
          syncAlert.textContent = `Restored! Added ${res.added.length} accounts.`;
          syncAlert.classList.remove('hidden');
        } catch (innerErr) {
          syncAlert.textContent = `Restore failed: ${(innerErr as Error).message}`;
          syncAlert.classList.remove('hidden');
        }
      };
      return;
    }
    syncAlert.textContent = `Sync merge error: ${(err as Error).message}`;
    syncAlert.classList.remove('hidden');
  }
});

// -------------------------------------------------------------
// Security & Preferences
// -------------------------------------------------------------

formChangePassword.addEventListener('submit', async (e) => {
  e.preventDefault();
  pwdError.classList.add('hidden');
  pwdSuccess.classList.add('hidden');

  const curr = pwdCurrent.value;
  const next = pwdNew.value;
  const conf = pwdConfirm.value;

  if (next !== conf) {
    pwdError.textContent = 'New passwords do not match.';
    pwdError.classList.remove('hidden');
    return;
  }

  try {
    await changePassword(curr, next);
    pwdCurrent.value = '';
    pwdNew.value = '';
    pwdConfirm.value = '';
    pwdSuccess.classList.remove('hidden');
    showToast('Master password successfully changed.');
  } catch (err) {
    pwdError.textContent = (err as Error).message;
    pwdError.classList.remove('hidden');
  }
});

async function loadPreferences(): Promise<void> {
  const settings = await getSettings();
  settingAutolock.value = String(settings.autoLockMinutes);
  settingLockSystem.checked = settings.lockOnSystemLock;
  settingLearnDomains.checked = settings.learnDomains;
}

btnSavePrefs.addEventListener('click', async () => {
  await updateSettings({
    autoLockMinutes: Number(settingAutolock.value),
    lockOnSystemLock: settingLockSystem.checked,
    learnDomains: settingLearnDomains.checked,
  });
  showToast('Preferences saved.');
});

btnDestroyVault.addEventListener('click', async () => {
  const confirmed = confirm(
    'ARE YOU ABSOLUTELY SURE?\n\nThis will completely delete your encrypted vault and all 2FA accounts stored on this computer. If you do not have an external backup, you will lose access to your 2FA tokens.',
  );
  if (!confirmed) return;

  const doubleConfirm = prompt('Type "DELETE" to permanently erase this vault:');
  if (doubleConfirm !== 'DELETE') {
    showToast('Action cancelled.');
    return;
  }

  await destroyVault();
  await clearSync();
  showToast('Vault destroyed. Reloading...');
  setTimeout(() => {
    window.location.reload();
  }, 1000);
});

// -------------------------------------------------------------
// Initialization
// -------------------------------------------------------------

async function init(): Promise<void> {
  await refreshSyncInfo();
  await loadPreferences();
}

init().catch(console.error);
