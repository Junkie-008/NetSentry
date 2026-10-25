/**
 * Minimal in-memory mock of the chrome extension APIs used by background.js,
 * good enough for integration tests in Node.
 */

function createMockChrome(options = {}) {
  const data = {};
  const listeners = {
    onUpdated: [],
    onRemoved: [],
    onBeforeNavigate: [],
    onChanged: [],
    onMessage: []
  };
  const calls = {
    executeScript: [],
    badgeText: [],
    badgeColor: [],
    tabsUpdate: []
  };

  function notifyChanged(changes, area) {
    for (const fn of listeners.onChanged) fn(changes, area);
  }

  const chrome = {
    runtime: {
      onMessage: {
        addListener(fn) {
          listeners.onMessage.push(fn);
        }
      },
      getURL: (p) => `chrome-extension://mock-extension-id/${p}`
    },
    tabs: {
      onUpdated: {
        addListener(fn) {
          listeners.onUpdated.push(fn);
        }
      },
      onRemoved: {
        addListener(fn) {
          listeners.onRemoved.push(fn);
        }
      },
      query: async () => (options.activeUrl ? [{ id: options.tabId || 1, url: options.activeUrl }] : []),
      update: async (tabId, props) => {
        calls.tabsUpdate.push({ tabId, ...props });
        return { id: tabId, ...props };
      }
    },
    webNavigation: {
      onBeforeNavigate: {
        addListener(fn) {
          listeners.onBeforeNavigate.push(fn);
        }
      }
    },
    storage: {
      local: {
        async get(keys) {
          if (keys == null) return { ...data };
          const list = Array.isArray(keys) ? keys : [keys];
          const out = {};
          for (const k of list) {
            if (k in data) out[k] = data[k];
          }
          return out;
        },
        async set(obj) {
          const changes = {};
          for (const [k, v] of Object.entries(obj)) {
            changes[k] = { oldValue: data[k], newValue: v };
            data[k] = v;
          }
          notifyChanged(changes, 'local');
        },
        async remove(key) {
          const list = Array.isArray(key) ? key : [key];
          const changes = {};
          for (const k of list) {
            if (k in data) {
              changes[k] = { oldValue: data[k], newValue: undefined };
              delete data[k];
            }
          }
          if (Object.keys(changes).length) notifyChanged(changes, 'local');
        }
      },
      onChanged: {
        addListener(fn) {
          listeners.onChanged.push(fn);
        }
      }
    },
    action: {
      setBadgeText(arg) {
        calls.badgeText.push(arg);
      },
      setBadgeBackgroundColor(arg) {
        calls.badgeColor.push(arg);
      }
    },
    scripting: {
      async executeScript(opts) {
        calls.executeScript.push(opts);
        return [{ result: undefined }];
      }
    }
  };

  const emit = {
    /** tabs.onUpdated equivalent */
    tabUpdated(tabId, url) {
      for (const fn of listeners.onUpdated) {
        fn(tabId, { status: 'complete' }, { id: tabId, url });
      }
    },
    /** webNavigation.onBeforeNavigate equivalent */
    beforeNavigate(tabId, url) {
      for (const fn of listeners.onBeforeNavigate) {
        fn({ tabId, url, frameId: 0, timeStamp: Date.now() });
      }
    },
    tabRemoved(tabId) {
      for (const fn of listeners.onRemoved) fn(tabId);
    },
    /** chrome.runtime.sendMessage from the popup; resolves with sendResponse value */
    message(request) {
      return new Promise((resolve) => {
        let responded = false;
        const respond = (value) => {
          if (!responded) {
            responded = true;
            resolve(value);
          }
        };
        for (const fn of listeners.onMessage) {
          fn(request, {}, respond);
        }
        if (!responded) setTimeout(() => respond(undefined), 25);
      });
    }
  };

  /** Direct storage write that also fires onChanged (like the popup does). */
  const writeStorage = (obj) => chrome.storage.local.set(obj);

  return { chrome, calls, data, emit, writeStorage };
}

/** Let queued promises/microtasks settle. */
async function flush(ms = 40) {
  await new Promise((r) => setTimeout(r, ms));
}

module.exports = { createMockChrome, flush };
