/**
 * In-memory mock of the Chrome extension APIs for Node/Vitest test environments.
 */

class MockStorageArea {
  private data: Record<string, unknown> = {};

  async get(keys: string | string[] | Record<string, unknown> | null): Promise<Record<string, unknown>> {
    if (keys === null) {
      return { ...this.data };
    }
    if (typeof keys === 'string') {
      return { [keys]: this.data[keys] };
    }
    if (Array.isArray(keys)) {
      const res: Record<string, unknown> = {};
      for (const k of keys) {
        if (k in this.data) {
          res[k] = this.data[k];
        }
      }
      return res;
    }
    const res: Record<string, unknown> = { ...keys };
    for (const k of Object.keys(keys)) {
      if (k in this.data) {
        res[k] = this.data[k];
      }
    }
    return res;
  }

  async set(items: Record<string, unknown>): Promise<void> {
    Object.assign(this.data, items);
  }

  async remove(keys: string | string[]): Promise<void> {
    const list = Array.isArray(keys) ? keys : [keys];
    for (const k of list) {
      delete this.data[k];
    }
  }

  async clear(): Promise<void> {
    this.data = {};
  }

  async setAccessLevel(_options: { accessLevel: string }): Promise<void> {
    // Mock no-op for tests
  }

  async getBytesInUse(_keys: unknown): Promise<number> {
    return JSON.stringify(this.data).length;
  }
}

const mockLocal = new MockStorageArea();
const mockSession = new MockStorageArea();
const mockSync = Object.assign(new MockStorageArea(), {
  QUOTA_BYTES: 102_400,
  QUOTA_BYTES_PER_ITEM: 8192,
});

(globalThis as unknown as { chrome: unknown }).chrome = {
  storage: {
    local: mockLocal,
    session: mockSession,
    sync: mockSync,
    onChanged: {
      addListener: () => {},
      removeListener: () => {},
    },
  },
  runtime: {
    onInstalled: { addListener: () => {} },
    onStartup: { addListener: () => {} },
    onMessage: { addListener: () => {} },
    openOptionsPage: () => {},
  },
  action: {
    setBadgeText: async () => {},
    setBadgeBackgroundColor: async () => {},
    openPopup: async () => {},
  },
  alarms: {
    create: async () => {},
    onAlarm: { addListener: () => {} },
  },
  idle: {
    onStateChanged: { addListener: () => {} },
  },
  commands: {
    onCommand: { addListener: () => {} },
  },
  tabs: {
    query: async () => [],
    sendMessage: async () => {},
    captureVisibleTab: async () => '',
  },
  scripting: {
    executeScript: async () => [],
  },
  windows: {
    WINDOW_ID_CURRENT: -2,
  },
};

export { mockLocal, mockSession, mockSync };
