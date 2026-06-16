// AlloChat Background Service Worker
const MSG_PREFIX   = 'AP1:';
const INDEXER_NODE = 'https://mainnet-idx.algonode.cloud';
const SESSION_KEY  = 'allochat_session';

// ── Session store getters and setters (using chrome.storage.session) ────────────
async function getSession() {
  const data = await new Promise(r => chrome.storage.session.get([SESSION_KEY], r));
  if (data && data[SESSION_KEY]) {
    return data[SESSION_KEY];
  }
  return {
    sk:         null, // Array of numbers
    addr:       null,
    unlockedAt: null,
    duration:   'session',
    autoLockMs: 5 * 60 * 1000,
    locked:     false
  };
}

async function saveSession(store) {
  await new Promise(r => chrome.storage.session.set({ [SESSION_KEY]: store }, r));
}

// ── Message handler ────────────────────────────────────────────────────────
chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  handleMessageAsync(msg, sender)
    .then(response => {
      sendResponse(response);
    })
    .catch(error => {
      console.error('[BG] Messenger error:', error);
      sendResponse({ ok: false, error: error.message });
    });
  return true; // Keeps the message channel open for async sendResponse
});

async function handleMessageAsync(msg, sender) {
  if (msg.type === 'SESSION_SET') {
    let sk = null;
    if (Array.isArray(msg.sk) && msg.sk.length === 64 && msg.sk.every(b => typeof b === 'number' && b >= 0 && b <= 255)) {
      sk = Array.from(msg.sk);
    } else if (msg.sk != null) {
      return { ok: false, error: 'invalid_sk' };
    }

    const store = await getSession();
    store.sk         = sk;
    store.addr       = typeof msg.addr === 'string' ? msg.addr.trim() : null;
    store.unlockedAt = Date.now();
    store.duration   = msg.duration || 'session';
    store.locked     = false;
    
    if (typeof msg.autoLockMs === 'number') {
      store.autoLockMs = msg.autoLockMs;
    }
    
    await saveSession(store);
    await scheduleAutoLock();
    return { ok: true };
  }

  if (msg.type === 'SESSION_GET') {
    await checkAutoLockExpiry();
    const store = await getSession();
    return {
      ok:       true,
      sk:       (!store.locked && store.sk) ? store.sk : null,
      addr:     store.locked ? null : store.addr,
      duration: store.duration,
      locked:   store.locked
    };
  }

  if (msg.type === 'SESSION_CLEAR') {
    const store = {
      sk:         null,
      addr:       null,
      unlockedAt: null,
      duration:   'session',
      autoLockMs: 5 * 60 * 1000,
      locked:     false
    };
    await saveSession(store);
    await chrome.alarms.clear('autolock');
    return { ok: true };
  }

  if (msg.type === 'USER_ACTIVITY') {
    const store = await getSession();
    if (store.addr && !store.locked) {
      store.unlockedAt = Date.now();
      await saveSession(store);
      await scheduleAutoLock();
    }
    return { ok: true };
  }

  if (msg.type === 'AUTOLOCK_CONFIG') {
    const store = await getSession();
    if (typeof msg.autoLockMs === 'number') {
      store.autoLockMs = msg.autoLockMs;
    }
    if (typeof msg.enabled === 'boolean') {
      if (!msg.enabled) {
        store.autoLockMs = 0;
        await saveSession(store);
        await chrome.alarms.clear('autolock');
        return { ok: true };
      } else {
        if (store.autoLockMs <= 0) {
          store.autoLockMs = 5 * 60 * 1000;
        }
      }
    }
    await saveSession(store);
    await scheduleAutoLock();
    return { ok: true };
  }

  if (msg.type === 'POPUP_OPENED') {
    await chrome.action.setBadgeText({ text: '' });
    await storageSet({ bgUnreadCount: 0 });
    return { ok: true };
  }

  if (msg.type === 'SET_BADGE') {
    const count = msg.count || 0;
    await chrome.action.setBadgeText({ text: count > 0 ? String(count) : '' });
    await chrome.action.setBadgeBackgroundColor({ color: '#f87171' });
    return { ok: true };
  }

  if (msg.type === 'CLEAR_BADGE') {
    await chrome.action.setBadgeText({ text: '' });
    await storageSet({ bgUnreadCount: 0 });
    return { ok: true };
  }

  return { error: 'unknown_message' };
}

// ── Auto-lock helpers ─────────────────────────────────────────────────────
async function scheduleAutoLock() {
  const store = await getSession();
  const ms = store.autoLockMs;
  if (!ms || ms <= 0 || !store.addr || store.locked) {
    await chrome.alarms.clear('autolock');
    return;
  }
  const elapsed   = Date.now() - (store.unlockedAt || Date.now());
  const remaining = Math.max(ms - elapsed, 1000); // Guard time
  
  await chrome.alarms.clear('autolock');
  await chrome.alarms.create('autolock', { when: Date.now() + remaining });
}

async function checkAutoLockExpiry() {
  const store = await getSession();
  if (!store.addr || store.locked) return;
  const ms = store.autoLockMs;
  if (!ms || ms <= 0) return;
  if (Date.now() - (store.unlockedAt || 0) >= ms) {
    await doAutoLock();
  }
}

async function doAutoLock() {
  console.log('[BG] Auto-lock triggered');
  const store = await getSession();
  store.locked = true;
  store.sk     = null;
  await saveSession(store);
  await chrome.alarms.clear('autolock');
}

// ── Polling alarm ─────────────────────────────────────────────────────────
function ensurePollAlarm() {
  chrome.alarms.get('poll', (existing) => {
    if (!existing) {
      chrome.alarms.create('poll', { periodInMinutes: 1 });
      console.log('[BG] Poll alarm created (1 min)');
    }
  });
}

chrome.runtime.onInstalled.addListener(ensurePollAlarm);
chrome.runtime.onStartup.addListener(ensurePollAlarm);
ensurePollAlarm();

// ── Alarm handler ─────────────────────────────────────────────────────────
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name === 'autolock') { 
    await doAutoLock(); 
    return; 
  }
  if (alarm.name !== 'poll') return;

  await runPoll();
});

async function runPoll() {
  const s = await storageGet(['algoAddress', 'seenTxIds', 'deletedConvs', 'bgUnreadCount']);
  if (!s.algoAddress) return;

  const myAddr       = s.algoAddress;
  const seenTxIds    = new Set(s.seenTxIds || []);
  const deletedConvs = s.deletedConvs || {};
  let bgUnread = typeof s.bgUnreadCount === 'number' ? s.bgUnreadCount : 0;

  let totalNew    = 0;
  const newSeenIds = [...seenTxIds];

  try {
    const pfx = encodeURIComponent(btoa(MSG_PREFIX));
    const r   = await fetch(
      `${INDEXER_NODE}/v2/transactions?address=${myAddr}&address-role=receiver&note-prefix=${pfx}&limit=50`
    );
    if (!r.ok) return;

    const txs = (await r.json()).transactions || [];

    for (const tx of txs) {
      if (seenTxIds.has(tx.id)) continue;
      if (!tx.note) continue;
      if (tx['payment-transaction']?.receiver !== myAddr) continue;

      const txMs      = (tx['round-time'] || 0) * 1000;
      const deletedTs = deletedConvs[tx.sender] || 0;
      if (deletedTs && txMs < deletedTs) continue;

      let raw = '';
      try { raw = atob(tx.note); } catch { continue; }
      if (!raw.startsWith(MSG_PREFIX)) continue;

      totalNew++;
      newSeenIds.push(tx.id);
    }

    await storageSet({ seenTxIds: newSeenIds.slice(-500) });

    if (totalNew > 0) {
      bgUnread += totalNew;
      await storageSet({ bgUnreadCount: bgUnread });
      await chrome.action.setBadgeText({ text: String(bgUnread) });
      await chrome.action.setBadgeBackgroundColor({ color: '#f87171' });
      console.log(`[BG] Poll: ${totalNew} new messages, badge=${bgUnread}`);
    }

  } catch (e) {
    console.warn('[BG] Poll error:', e.message);
  }
}

// ── Storage wrappers ───────────────────────────────────────────────────────
function storageGet(keys) {
  return new Promise(r => chrome.storage.local.get(keys, r));
}
function storageSet(obj) {
  return new Promise(r => chrome.storage.local.set(obj, r));
}
