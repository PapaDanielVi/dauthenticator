import { DEFAULT_SETTINGS, type Settings } from './types';

export const SETTINGS_STORAGE_KEY = 'dauth.settings';

export async function getSettings(): Promise<Settings> {
  const stored = await chrome.storage.local.get(SETTINGS_STORAGE_KEY);
  const value = stored[SETTINGS_STORAGE_KEY] as Partial<Settings> | undefined;
  return { ...DEFAULT_SETTINGS, ...(value ?? {}) };
}

export async function updateSettings(patch: Partial<Settings>): Promise<Settings> {
  const next = { ...(await getSettings()), ...patch };
  await chrome.storage.local.set({ [SETTINGS_STORAGE_KEY]: next });
  return next;
}
