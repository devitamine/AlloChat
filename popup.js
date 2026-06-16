document.addEventListener('DOMContentLoaded', () => {

  // ── Constants ─────────────────────────────────────────────────────────────
  const ALGOD_NODE   = 'https://mainnet-api.algonode.cloud';
  const INDEXER_NODE = 'https://mainnet-idx.algonode.cloud';
  const MSG_PREFIX   = 'AP1:';

  // ── State ─────────────────────────────────────────────────────────────────
  let contacts        = [];
  let pollingTimer    = null;
  let contactsPollingTimer = null;   // poll unread counts on the contact list
  let renderedTxIds   = new Set();
  let currentConvAddr = null;
  let _editingContactAddress = null;   // Original address when editing a contact
  let _userIsScrolledUp   = false;   // whether the user scrolled up (viewing history)
  let _pendingNewMsgIds   = [];      // IDs of new messages arriving while viewing history
  let unlockDuration  = 'session';
  let unlockTimer     = null;

  // ── Auto-lock ─────────────────────────────────────────────────────────────
  // Auto-lock timer lives in the background SW (survives closing the popup).
  // The popup only: notifies the SW of activity and checks locked state on startup.
  const AUTOLOCK_DEFAULT_MS = 5 * 60 * 1000;
  let autoLockMs      = AUTOLOCK_DEFAULT_MS;
  let autoLockEnabled = true;

  // Throttle: send USER_ACTIVITY to SW at most once every 10s
  let _lastActivitySent = 0;
  function onUserActivity() {
    if (!window._addr) return;
    const now = Date.now();
    if (now - _lastActivitySent < 10000) return;
    _lastActivitySent = now;
    bgMessage({ type: 'USER_ACTIVITY' }).catch(() => {});
  }
  document.addEventListener('click',   onUserActivity, true);
  document.addEventListener('keydown', onUserActivity, true);

  // unreadMap: { [address]: { count: number, lastSeenTs: number } }
  // lastSeenTs = ms timestamp when the user last opened the conversation with this contact
  // Messages older than lastSeenTs are ignored when counting unread messages
  let unreadMap = {};


  // ── DOM helper ────────────────────────────────────────────────────────────
  const $ = id => document.getElementById(id);

  // ── View navigation ───────────────────────────────────────────────────────
  function showView(id) {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    const el = $(id);
    if (el) el.classList.add('active');
  }

  // ══════════════════════════════════════════════════════════════════
  // CRYPTO & ENCRYPTION
  // ══════════════════════════════════════════════════════════════════

  async function deriveStorageKey(pw, saltHex = null) {
    const enc  = new TextEncoder();
    const saltBytes = saltHex
      ? Uint8Array.from(saltHex.match(/.{2}/g), h => parseInt(h, 16))
      : enc.encode('algopriv_kdf_v1:');   // legacy-only fallback
    const keyMat = await crypto.subtle.importKey(
      'raw', enc.encode(pw), 'PBKDF2', false, ['deriveKey']
    );
    return crypto.subtle.deriveKey(
      { name: 'PBKDF2', hash: 'SHA-256', salt: saltBytes, iterations: 100000 },
      keyMat,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  function generateSalt() {
    return Array.from(crypto.getRandomValues(new Uint8Array(16)))
      .map(b => b.toString(16).padStart(2, '0')).join('');
  }

  const _ENC_MAGIC = [0x41, 0x50]; // 'AP'

  async function encryptMnemonic(mn, pw) {
    const salt = generateSalt();
    const key  = await deriveStorageKey(pw, salt);
    const iv   = crypto.getRandomValues(new Uint8Array(12));
    const ct   = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(mn));
    const saltBytes = Uint8Array.from(salt.match(/.{2}/g), h => parseInt(h, 16));
    const buf  = new Uint8Array(2 + 16 + 12 + ct.byteLength);
    buf.set(_ENC_MAGIC, 0);
    buf.set(saltBytes, 2);
    buf.set(iv, 18);
    buf.set(new Uint8Array(ct), 30);
    return btoa(String.fromCharCode(...buf));
  }

  async function decryptMnemonic(b64, pw) {
    const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    if (buf[0] === _ENC_MAGIC[0] && buf[1] === _ENC_MAGIC[1]) {
      const saltHex = Array.from(buf.slice(2, 18))
        .map(b => b.toString(16).padStart(2, '0')).join('');
      const key = await deriveStorageKey(pw, saltHex);
      const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(18, 30) }, key, buf.slice(30));
      return new TextDecoder().decode(pt);
    }
    const rawLegacy = await crypto.subtle.digest('SHA-256',
      new TextEncoder().encode('algopriv_kdf_v1:' + pw));
    const keyLegacy = await crypto.subtle.importKey('raw', rawLegacy, { name: 'AES-GCM' }, false, ['decrypt']);
    const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, keyLegacy, buf.slice(12));
    return new TextDecoder().decode(pt);
  }

  async function deriveMsgKey(addrA, addrB) {
    const [a, b] = [addrA, addrB].sort();   // canonical ordering
    const raw  = await crypto.subtle.digest('SHA-256',
      new TextEncoder().encode('algopriv:pair:' + a + ':' + b));
    const base = await crypto.subtle.importKey('raw', raw, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256',
        salt: new TextEncoder().encode('AlgoPrivChatV2'),
        info: new TextEncoder().encode('msg-key-v2') },
      base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
    );
  }

  async function encryptMsg(text, myAddr, theirAddr) {
    const key = await deriveMsgKey(myAddr, theirAddr);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, new TextEncoder().encode(text));
    const buf = new Uint8Array(12 + ct.byteLength);
    buf.set(iv); buf.set(new Uint8Array(ct), 12);
    return MSG_PREFIX + btoa(String.fromCharCode(...buf));
  }

  async function decryptMsg(encPart, myAddr, theirAddr) {
    const key = await deriveMsgKey(myAddr, theirAddr);
    const buf = Uint8Array.from(atob(encPart), c => c.charCodeAt(0));
    const pt  = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: buf.slice(0, 12) }, key, buf.slice(12));
    return new TextDecoder().decode(pt);
  }

  async function hashPw(pw) {
    const enc     = new TextEncoder();
    const keyMat  = await crypto.subtle.importKey('raw', enc.encode(pw), 'PBKDF2', false, ['deriveBits']);
    const bits    = await crypto.subtle.deriveBits(
      { name: 'PBKDF2', hash: 'SHA-256',
        salt: enc.encode('algopriv_login_v2'),
        iterations: 100000 },
      keyMat, 256
    );
    return Array.from(new Uint8Array(bits)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  async function hashPwLegacy(pw) {
    const raw = await crypto.subtle.digest('SHA-256',
      new TextEncoder().encode('algopriv_login_v1:' + pw));
    return Array.from(new Uint8Array(raw)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  // ── Address validation ──────────────────────────────────────────────
  function cleanAddr(raw) {
    if (!raw) return '';
    if (typeof raw === 'string') return raw.trim();
    if (raw instanceof Uint8Array) return algosdk.encodeAddress(raw);
    if (raw.publicKey instanceof Uint8Array) return algosdk.encodeAddress(raw.publicKey);
    if (raw.addr) return cleanAddr(raw.addr);
    return String(raw).trim();
  }

  function shortAddr(a) {
    const s = cleanAddr(a);
    return s.length >= 10 ? s.slice(0, 6) + '…' + s.slice(-4) : s;
  }

  function esc(t) {
    return String(t)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');
  }

  function isValidAlgoAddr(addr) {
    try { algosdk.decodeAddress(addr); return true; } catch { return false; }
  }

  function getNick(address) {
    const c = cleanAddr(address);
    if (window._addr && c === cleanAddr(window._addr)) {
      return 'Encrypted Notes (Me)';
    }
    const f = contacts.find(x => cleanAddr(x.address) === c);
    return f ? f.nick : shortAddr(c);
  }

  function avatarColor(address) {
    const h = cleanAddr(address).split('').reduce((a, c) => a + c.charCodeAt(0), 0) % 360;
    return {
      bg: `linear-gradient(135deg,hsl(${h},55%,28%),hsl(${(h + 55) % 360},65%,22%))`,
      txt: `hsl(${h},75%,78%)`
    };
  }

  function makeAvatar(address, nick) {
    const c = avatarColor(address);
    return { bg: c.bg, color: c.txt, letter: (nick || '?')[0].toUpperCase() };
  }

  // ══════════════════════════════════════════════════════════════════
  // SESSION / UNLOCK
  // ══════════════════════════════════════════════════════════════════

  async function bgMessage(msg, timeoutMs = 4000) {
    for (let attempt = 0; attempt < 2; attempt++) {
      try {
        return await new Promise((resolve, reject) => {
          const timer = setTimeout(() => reject(new Error('SW timeout')), timeoutMs);
          try {
            chrome.runtime.sendMessage(msg, (resp) => {
              clearTimeout(timer);
              if (chrome.runtime.lastError) {
                reject(new Error(chrome.runtime.lastError.message));
              } else {
                resolve(resp);
              }
            });
          } catch (e) {
            clearTimeout(timer);
            reject(e);
          }
        });
      } catch (e) {
        if (attempt === 0) {
          await new Promise(r => setTimeout(r, 500));
          continue;
        }
        throw e;
      }
    }
  }

  async function unlockSession(pw) {
    const s = await storageGet(['encryptedMnemonic', 'passwordHash', 'pwHashVersion']);
    if (!s.encryptedMnemonic) throw new Error('No account found.');
    const h = await hashPw(pw);
    if (s.pwHashVersion !== 2) {
      const hLegacy = await hashPwLegacy(pw);
      if (s.passwordHash !== hLegacy) throw new Error('Incorrect passcode.');
      const mn = await decryptMnemonic(s.encryptedMnemonic, pw);
      const newEm = await encryptMnemonic(mn, pw);
      await storageSet({ passwordHash: h, pwHashVersion: 2, encryptedMnemonic: newEm });
      s.encryptedMnemonic = newEm;
    } else {
      if (s.passwordHash !== h) throw new Error('Incorrect passcode.');
    }
    const mn = await decryptMnemonic(s.encryptedMnemonic, pw);
    const ac = algosdk.mnemonicToSecretKey(mn);
    window._sk   = ac.sk;
    window._addr = cleanAddr(ac.addr);

    if (unlockDuration !== 'once') {
      try {
        await bgMessage({
          type: 'SESSION_SET',
          sk:   Array.from(ac.sk),
          addr: window._addr,
          duration: unlockDuration,
          autoLockMs: autoLockEnabled ? autoLockMs : 0
        });
      } catch (e) {
        console.warn('[Unlock] SW session save failed:', e.message);
      }
    }
  }

  async function lockSession() {
    window._sk   = null;
    window._addr = null;
    clearTimeout(unlockTimer);
    try { await bgMessage({ type: 'SESSION_CLEAR' }); } catch {}
  }

  function showLockScreen() {
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    $('view-lock').classList.add('active');
    $('lock-password').value = '';
    $('lock-error').textContent = '';
    setTimeout(() => $('lock-password').focus(), 80);
  }

  async function loadAutoLockSettings() {
    const s = await storageGet(['autoLockEnabled', 'autoLockMs']);
    autoLockEnabled = s.autoLockEnabled !== false;
    autoLockMs      = (typeof s.autoLockMs === 'number') ? s.autoLockMs : AUTOLOCK_DEFAULT_MS;
    syncAutoLockUI();
  }

  function syncAutoLockUI() {
    const toggle = $('autolock-toggle');
    const sel    = $('autolock-time-select');
    if (toggle) toggle.checked = autoLockEnabled;
    if (sel)    sel.value      = String(autoLockMs);
    if ($('autolock-time-row')) {
      $('autolock-time-row').style.opacity        = autoLockEnabled ? '1' : '0.4';
      $('autolock-time-row').style.pointerEvents  = autoLockEnabled ? '' : 'none';
    }
  }

  async function tryRestoreSessionKey() {
    try {
      const resp = await bgMessage({ type: 'SESSION_GET' }, 3000);
      if (resp && resp.locked) {
        return 'locked';
      }
      if (resp && resp.addr) {
        window._addr = cleanAddr(resp.addr);
        window._sk   = resp.sk ? new Uint8Array(resp.sk) : null;
        return true;
      }
    } catch (e) {
      console.warn('[Popup] Could not restore session from SW:', e.message);
    }
    return false;
  }

  function isUnlocked() {
    return !!window._addr;
  }

  function showUnlockOrInput() {
    const hasAddr = !!window._addr;
    const hasSk   = !!window._sk;

    if (hasAddr && hasSk) {
      $('unlock-banner').classList.remove('on');
      $('chat-inputbar').classList.add('on');
    } else {
      $('unlock-banner').classList.add('on');
      $('chat-inputbar').classList.remove('on');
    }
  }

  document.querySelectorAll('.unlock-opt').forEach(opt => {
    opt.addEventListener('click', () => {
      document.querySelectorAll('.unlock-opt').forEach(o => o.classList.remove('selected'));
      opt.classList.add('selected');
      unlockDuration = opt.dataset.dur;
    });
  });

  function storageGet(keys) {
    return new Promise(r => chrome.storage.local.get(keys, r));
  }
  function storageSet(obj) {
    return new Promise(r => chrome.storage.local.set(obj, r));
  }

  // ══════════════════════════════════════════════════════════════════
  // DELETED CONVERSATIONS & HISTORY
  // ══════════════════════════════════════════════════════════════════

  async function getDeletedConvs() {
    const s = await storageGet(['deletedConvs']);
    return s.deletedConvs || {};
  }

  async function deleteConv(theirAddr) {
    const dc = await getDeletedConvs();
    dc[theirAddr] = Date.now();
    await storageSet({ deletedConvs: dc });
  }

  async function restoreConv(theirAddr) {
    const dc = await getDeletedConvs();
    delete dc[theirAddr];
    await storageSet({ deletedConvs: dc });
  }

  async function getConvDeletedTs(theirAddr) {
    const dc = await getDeletedConvs();
    return dc[theirAddr] || 0;
  }

  $('btn-delete-conv').addEventListener('click', async () => {
    if (!currentConvAddr) return;
    if (!confirm('Hide the history of this conversation? Messages remain on the blockchain, but will not be shown in this session.')) return;
    await deleteConv(currentConvAddr);
    renderedTxIds = new Set();
    $('chat-window').innerHTML = `
      <div class="chat-ph">
        <span class="material-icons">delete_outline</span>
        Chat history cleared locally.
      </div>`;
    $('conv-deleted-notice').style.display = 'flex';
    fetchConv(currentConvAddr);
  });

  $('btn-restore-conv').addEventListener('click', async () => {
    if (!currentConvAddr) return;
    await restoreConv(currentConvAddr);
    renderedTxIds = new Set();
    $('conv-deleted-notice').style.display = 'none';
    $('chat-window').innerHTML = `<div class="chat-ph"><span class="material-icons">hourglass_empty</span>Loading…</div>`;
    fetchConv(currentConvAddr);
  });

  function setBadge(count) {
    chrome.runtime.sendMessage({ type: 'SET_BADGE', count }, () => {});
  }

  function clearBadge() {
    chrome.runtime.sendMessage({ type: 'POPUP_OPENED' }, () => {});
    chrome.action.setBadgeText({ text: '' });
  }

  async function fetchBalance(a) {
    try {
      const info = await new algosdk.Algodv2('', ALGOD_NODE, '').accountInformation(a).do();
      return (Number(info.amount) / 1e6).toFixed(4) + ' ALGO';
    } catch { return '— ALGO'; }
  }

  async function refreshBalance() {
    const s = await storageGet(['algoAddress']);
    if (!s.algoAddress) return;
    const bal = await fetchBalance(cleanAddr(s.algoAddress));
    const els = [$('balance-display'), $('settings-balance')];
    els.forEach(el => { if (el) el.textContent = bal; });
  }

  // ══════════════════════════════════════════════════════════════════
  // CONTACTS MANAGEMENT
  // ══════════════════════════════════════════════════════════════════

  async function loadContacts() {
    const s = await storageGet(['chatContacts', 'unreadMap']);
    contacts  = s.chatContacts || [];
    const raw = s.unreadMap || {};
    unreadMap = {};
    for (const [addr, val] of Object.entries(raw)) {
      if (typeof val === 'number') {
        unreadMap[addr] = { count: val, lastSeenTs: 0 };
      } else {
        unreadMap[addr] = val;
      }
    }
    renderContacts();
  }

  function saveUnreadMap() {
    storageSet({ unreadMap });
  }

  function renderContacts() {
    const box = $('contacts-container');
    box.innerHTML = '';

    const query = ($('contact-search-input')?.value || '').toLowerCase().trim();

    // Render "Encrypted Notes (Me)" row first if logged in
    const myAddr = window._addr;
    if (myAddr) {
      const notesName = 'encrypted notes (me)';
      const notesDesc = 'secure auto-chat & scratchpad';
      const termMatch = !query ||
                        notesName.includes(query) ||
                        notesDesc.includes(query) ||
                        myAddr.toLowerCase().includes(query) ||
                        'notes'.includes(query) ||
                        'saved'.includes(query) ||
                        'me'.includes(query) ||
                        'self'.includes(query);

      if (termMatch) {
        const row = document.createElement('div');
        row.className = 'contact-row';
        row.style.borderLeft = '3.5px solid var(--acc)';
        row.style.background = 'linear-gradient(90deg, var(--acc-dim) 0%, transparent 100%)';
        
        row.innerHTML = `
          <div class="contact-avatar-wrap">
            <div class="contact-avatar" style="background: linear-gradient(135deg, #1e293b 0%, #0f172a 100%); color: var(--acc); border: 1.5px solid var(--acc-glow); box-shadow: 0 0 6px var(--acc-glow);">
              <span class="material-icons" style="font-size:15px; margin-top:1px;">bookmark</span>
            </div>
          </div>
          <div class="contact-body">
            <div class="contact-name" style="color: var(--acc); font-weight: 600; display: flex; align-items: center; gap: 4px;">
              Encrypted Notes <span style="font-size: 10px; font-weight: 500; background: rgba(0, 240, 255, 0.15); color: var(--acc); padding: 1px 5px; border-radius: 4px; text-transform: uppercase;">Me</span>
            </div>
            <div class="contact-addr" style="color: var(--g8); font-size:10.5px;">Auto-encrypted cloud & scratchpad</div>
          </div>
        `;

        row.addEventListener('click', () => {
          unreadMap[myAddr] = { count: 0, lastSeenTs: Date.now() };
          saveUnreadMap();
          renderContacts();
          $('chat-recipient').value = myAddr;
          openChat(myAddr);
        });

        box.appendChild(row);
      }
    }

    // Filter regular contacts based on search query
    const filtered = contacts.filter(c => {
      if (!query) return true;
      return c.nick.toLowerCase().includes(query) || c.address.toLowerCase().includes(query);
    });

    // Sort: Pinned first, then alphabetically by nick
    filtered.sort((a, b) => {
      const pinA = !!a.pinned;
      const pinB = !!b.pinned;
      if (pinA !== pinB) {
        return pinA ? -1 : 1;
      }
      return a.nick.localeCompare(b.nick, undefined, { sensitivity: 'base' });
    });

    if (!filtered.length && !myAddr) {
      box.innerHTML = `
        <div class="no-contacts">
          <span class="material-icons">forum</span>
          No contacts found.<br>Add your first contact below.
        </div>`;
      return;
    } else if (!filtered.length && query) {
      if (!myAddr || (myAddr && !('encrypted notes (me)'.includes(query) || myAddr.toLowerCase().includes(query)))) {
        box.innerHTML = `
          <div class="no-contacts" style="padding: 24px 10px;">
            <span class="material-icons" style="font-size:24px; color: var(--g5); margin-bottom: 6px;">search_off</span>
            No contacts match "${esc(query)}"
          </div>`;
        return;
      }
    }

    filtered.forEach((c, i) => {
      // Find index in original contacts
      const originalIdx = contacts.findIndex(x => x.address === c.address);

      const av     = makeAvatar(c.address, c.nick);
      const row    = document.createElement('div');
      row.className = 'contact-row';
      const entry  = unreadMap[c.address] || { count: 0, lastSeenTs: 0 };
      const unread = entry.count || 0;

      row.innerHTML = `
        <div class="contact-avatar-wrap">
          <div class="contact-avatar" style="background:${av.bg};color:${av.color}">${av.letter}</div>
          ${unread > 0 ? '<span class="contact-unread-dot"></span>' : ''}
        </div>
        <div class="contact-body">
          <div class="contact-name" style="display:flex;align-items:center;gap:4px;">
            ${esc(c.nick)}
            ${c.pinned ? `<span class="material-icons" style="font-size:11px;color:var(--amber);" title="Pinned">push_pin</span>` : ''}
          </div>
          <div class="contact-addr">
            ${shortAddr(c.address)}
            ${c.note ? `<span class="contact-note-badge" title="${esc(c.note)}">${esc(c.note)}</span>` : ''}
          </div>
        </div>
        ${unread > 0 ? `<div class="contact-unread">${unread}</div>` : ''}
        <div style="display:flex;align-items:center;">
          <button class="contact-pin" title="${c.pinned ? 'Unpin contact' : 'Pin contact'}">
            <span class="material-icons" style="font-size:14px;color:${c.pinned ? 'var(--amber)' : 'var(--g6)'};">push_pin</span>
          </button>
          <button class="contact-edit" title="Edit contact">
            <span class="material-icons" style="font-size:14px;">edit</span>
          </button>
          <button class="contact-del" title="Delete contact">✕</button>
        </div>
      `;

      row.addEventListener('click', ev => {
        if (ev.target.closest('.contact-del') || ev.target.closest('.contact-edit') || ev.target.closest('.contact-pin')) return;
        unreadMap[c.address] = { count: 0, lastSeenTs: Date.now() };
        saveUnreadMap();
        renderContacts();
        $('chat-recipient').value = c.address;
        openChat(c.address);
      });

      row.querySelector('.contact-pin').addEventListener('click', async ev => {
        ev.stopPropagation();
        c.pinned = !c.pinned;
        if (originalIdx !== -1) {
          contacts[originalIdx].pinned = c.pinned;
        } else {
          const orig = contacts.find(x => x.address === c.address);
          if (orig) orig.pinned = c.pinned;
        }
        await storageSet({ chatContacts: contacts });
        renderContacts();
      });

      row.querySelector('.contact-edit').addEventListener('click', ev => {
        ev.stopPropagation();
        _editingContactAddress = c.address;
        $('contact-nick').value = c.nick;
        $('contact-address').value = c.address;
        if ($('contact-note')) $('contact-note').value = c.note || '';

        // Open the form
        $('add-contact-form').classList.add('open');
        $('toggle-add-contact').classList.add('open');

        // Update titles to reflect editing
        $('toggle-add-contact').innerHTML = '<span class="material-icons">edit</span> Edit Contact Details';
        $('btn-add-contact').innerHTML = '<span class="material-icons">check</span> Update Contact';
        
        $('contact-nick').focus();
      });

      row.querySelector('.contact-del').addEventListener('click', async ev => {
        ev.stopPropagation();
        if (originalIdx !== -1) {
          contacts.splice(originalIdx, 1);
          await storageSet({ chatContacts: contacts });
          renderContacts();
        }
      });

      box.appendChild(row);
    });
  }

  const searchInput = $('contact-search-input');
  const clearSearchBtn = $('btn-clear-search');
  if (searchInput && clearSearchBtn) {
    searchInput.addEventListener('input', () => {
      clearSearchBtn.style.display = searchInput.value ? 'flex' : 'none';
      renderContacts();
    });
    clearSearchBtn.addEventListener('click', () => {
      searchInput.value = '';
      clearSearchBtn.style.display = 'none';
      renderContacts();
      searchInput.focus();
    });
  }

  $('btn-add-contact').addEventListener('click', addContact);
  [$('contact-nick'), $('contact-address'), $('contact-note')].forEach(inp => {
    inp?.addEventListener('keydown', e => { if (e.key === 'Enter') addContact(); });
  });

  async function addContact() {
    const nick = $('contact-nick').value.trim();
    const a58  = $('contact-address').value.trim();
    const note = $('contact-note') ? $('contact-note').value.trim() : '';

    if (!nick) { $('contact-nick').focus(); return; }
    if (!a58)  { $('contact-address').focus(); return; }
    if (!isValidAlgoAddr(a58)) {
      alert(`Invalid Algorand address.`);
      return;
    }

    if (_editingContactAddress) {
      contacts = contacts.filter(c => cleanAddr(c.address) !== cleanAddr(_editingContactAddress));
      _editingContactAddress = null;
    }

    contacts = contacts.filter(c => cleanAddr(c.address) !== cleanAddr(a58));
    contacts.push({ nick, address: a58, note });
    await storageSet({ chatContacts: contacts });

    $('contact-nick').value    = '';
    $('contact-address').value = '';
    if ($('contact-note')) $('contact-note').value = '';

    // Revert form state back to Add Contact
    $('toggle-add-contact').innerHTML = '<span class="material-icons">chevron_right</span> Add Contact';
    $('btn-add-contact').innerHTML = '<span class="material-icons">check</span> Save Contact';

    renderContacts();

    $('add-contact-form').classList.remove('open');
    $('toggle-add-contact').classList.remove('open');
  }

  $('toggle-add-contact').addEventListener('click', () => {
    _editingContactAddress = null;
    $('contact-nick').value    = '';
    $('contact-address').value = '';
    if ($('contact-note')) $('contact-note').value = '';
    $('toggle-add-contact').innerHTML = '<span class="material-icons">chevron_right</span> Add Contact';
    $('btn-add-contact').innerHTML = '<span class="material-icons">check</span> Save Contact';
    $('add-contact-form').classList.toggle('open');
    $('toggle-add-contact').classList.toggle('open');
  });

  // ── Contacts Import/Export ────────────────────────────────────────────────

  async function deriveContactsKey(sk) {
    const seed = sk.slice(0, 32);
    const keyMat = await crypto.subtle.importKey('raw', seed, 'HKDF', false, ['deriveKey']);
    return crypto.subtle.deriveKey(
      {
        name: 'HKDF',
        hash: 'SHA-256',
        salt: new TextEncoder().encode('AlgoPrivContacts'),
        info: new TextEncoder().encode('contacts-v1')
      },
      keyMat,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  const CONTACTS_HEADER = 'APCONTACTS1\n';

  async function encryptContactsPayload(plaintext, sk) {
    const key = await deriveContactsKey(sk);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt(
      { name: 'AES-GCM', iv },
      key,
      new TextEncoder().encode(plaintext)
    );
    const buf = new Uint8Array(12 + ct.byteLength);
    buf.set(iv);
    buf.set(new Uint8Array(ct), 12);
    return CONTACTS_HEADER + btoa(String.fromCharCode(...buf));
  }

  async function decryptContactsPayload(fileText, sk) {
    if (!fileText.startsWith(CONTACTS_HEADER)) {
      throw new Error('Unknown file format - expected APCONTACTS1 header.');
    }
    const b64 = fileText.slice(CONTACTS_HEADER.length).trim();
    const buf = Uint8Array.from(atob(b64), c => c.charCodeAt(0));
    const key = await deriveContactsKey(sk);
    const pt  = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: buf.slice(0, 12) },
      key,
      buf.slice(12)
    );
    return new TextDecoder().decode(pt);
  }

  async function applyContactsText(plaintext) {
    const lines = plaintext.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
    let imported = 0;
    const errors = [];

    for (const line of lines) {
      const sep = line.indexOf('|');
      if (sep === -1) { errors.push('Invalid line: "' + line.slice(0, 40) + '"'); continue; }
      const nick = line.slice(0, sep).trim();
      const addr = line.slice(sep + 1).trim();
      if (!nick)                  { errors.push('Missing nickname in line: "' + line.slice(0, 40) + '"'); continue; }
      if (!isValidAlgoAddr(addr)) { errors.push('Invalid Algorand address: "' + addr.slice(0, 20) + '..."'); continue; }
      const exists = contacts.find(c => cleanAddr(c.address) === addr);
      if (exists) { exists.nick = nick; } else { contacts.push({ nick, address: addr }); }
      imported++;
    }

    await storageSet({ chatContacts: contacts });
    renderContacts();
    return { imported, errors };
  }

  async function exportContacts() {
    if (!contacts.length) { alert('No contacts available to export.'); return; }

    const lines     = contacts.map(c => c.nick + '|' + c.address).join('\n') + '\n';
    const sk        = window._sk;   // Uint8Array(64) or null

    let content, filename, mime;

    if (sk) {
      try {
        content  = await encryptContactsPayload(lines, sk);
        filename = 'allochat_contacts.enc.txt';
        mime     = 'text/plain;charset=utf-8';
      } catch (e) {
        alert('Encryption error: ' + e.message);
        return;
      }
    } else {
      content  = '# AlloChat contacts export (UNENCRYPTED)\n' + lines;
      filename = 'allochat_contacts.txt';
      mime     = 'text/plain;charset=utf-8';
      if (!confirm('This account does not have a session private key (e.g. read-only account),\nso the exported contacts will be UNENCRYPTED.\n\nDo you want to proceed?')) return;
    }

    const blob = new Blob([content], { type: mime });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href = url; a.download = filename;
    document.body.appendChild(a); a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    const btn = $('btn-export-contacts');
    const was = btn.innerHTML;
    btn.innerHTML = '<span class="material-icons">check</span> Saved';
    btn.disabled  = true;
    setTimeout(() => { btn.innerHTML = was; btn.disabled = false; }, 2000);
  }

  async function importContacts(file) {
    const fileText = await file.text();
    const sk       = window._sk;

    let plaintext;

    if (fileText.startsWith(CONTACTS_HEADER)) {
      if (!sk) {
        alert('This file is encrypted with an AlloChat account key.\n\nPlease unlock your account (enter passcode) and try again.');
        return;
      }
      try {
        plaintext = await decryptContactsPayload(fileText, sk);
      } catch (e) {
        alert('Failed to decrypt file: ' + e.message);
        return;
      }
    } else if (fileText.includes('|')) {
      plaintext = fileText;
    } else {
      alert('Unknown file format.');
      return;
    }

    const { imported, errors } = await applyContactsText(plaintext);
    let msg = 'Imported ' + imported + ' contacts.';
    if (errors.length) msg += '\n\nSkipped ' + errors.length + ' lines:\n' + errors.slice(0, 5).join('\n');
    alert(msg);
  }

  $('btn-export-contacts').addEventListener('click', exportContacts);
  $('btn-import-contacts').addEventListener('click', () => $('import-contacts-file').click());
  $('import-contacts-file').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    await importContacts(file);
    e.target.value = '';
  });

  // ── Lock & Unlock Screen ──────────────────────────────────────────────────
  $('btn-lock-unlock').addEventListener('click', handleLockUnlock);
  $('lock-password').addEventListener('keydown', e => {
    if (e.key === 'Enter') handleLockUnlock();
    $('lock-error').textContent = '';
  });

  async function handleLockUnlock() {
    const pw  = $('lock-password').value;
    const btn = $('btn-lock-unlock');
    if (!pw) { $('lock-error').textContent = 'Enter passcode.'; return; }
    btn.disabled = true;
    btn.textContent = 'Verifying…';
    try {
       await loadAutoLockSettings();
       await unlockSession(pw);
       $('lock-password').value = '';
       $('lock-error').textContent = '';
       const r = await storageGet(['username', 'algoAddress']);
       await showMainApp(r.username, r.algoAddress);
    } catch (e) {
       $('lock-error').textContent = 'Incorrect passcode.';
       $('lock-password').value = '';
       $('lock-password').focus();
    } finally {
       btn.disabled = false;
       btn.textContent = 'Unlock';
    }
  }

  $('autolock-toggle').addEventListener('change', async (e) => {
    autoLockEnabled = e.target.checked;
    await storageSet({ autoLockEnabled });
    syncAutoLockUI();
    bgMessage({ type: 'AUTOLOCK_CONFIG', enabled: autoLockEnabled, autoLockMs }).catch(() => {});
  });

  $('autolock-time-select').addEventListener('change', async (e) => {
    autoLockMs = parseInt(e.target.value, 10);
    await storageSet({ autoLockMs });
    if (autoLockEnabled) {
      bgMessage({ type: 'AUTOLOCK_CONFIG', enabled: true, autoLockMs }).catch(() => {});
    }
  });

  // ══════════════════════════════════════════════════════════════════
  // STARTUP SEQUENCE
  // ══════════════════════════════════════════════════════════════════

  (async () => {
    try {
      const r = await storageGet(['algoAddress', 'username']);
      if (r.algoAddress && r.username) {
        let sessionResult = false;
        try {
          sessionResult = await Promise.race([
            tryRestoreSessionKey(),
            new Promise(res => setTimeout(() => res(false), 1500))
          ]);
        } catch {}

        if (sessionResult === true) {
          showMainApp(r.username, r.algoAddress);
        } else {
          showLockScreen();
        }
      } else {
        showView('view-auth');
      }
    } catch (e) {
      console.error('[Startup] Error:', e);
      showView('view-auth');
    }
  })();

  $('link-go-to-import').addEventListener('click', () => showView('view-import'));
  $('link-go-to-create').addEventListener('click', () => showView('view-auth'));

  $('btn-create').addEventListener('click', async () => {
    const un = $('username').value.trim();
    const pw = $('password').value;
    if (!un || !pw) { alert('Please fill in nickname and passcode.'); return; }
    if (pw.length < 6) { alert('Passcode must be at least 6 characters.'); return; }
    try {
      const ac  = algosdk.generateAccount();
      const mn  = algosdk.secretKeyToMnemonic(ac.sk);
      const a   = cleanAddr(ac.addr);
      const [em, ph] = await Promise.all([encryptMnemonic(mn, pw), hashPw(pw)]);
      await storageSet({ username: un, algoAddress: a, encryptedMnemonic: em, passwordHash: ph, pwHashVersion: 2 });
      showMainApp(un, a);
    } catch (e) { alert('Error: ' + e.message); }
  });

  $('btn-import').addEventListener('click', async () => {
    const un   = $('import-username').value.trim();
    const pw   = $('import-password').value;
    const seed = $('import-seed').value.trim();
    if (!un || !pw || !seed) { alert('Please fill in all fields.'); return; }
    if (pw.length < 6) { alert('Passcode must be at least 6 characters.'); return; }

    const btn = $('btn-import');
    btn.disabled = true;
    btn.textContent = 'Importing…';

    try {
      let ac;
      try {
        ac = algosdk.mnemonicToSecretKey(seed);
      } catch (seedErr) {
        throw new Error('Invalid SEED - check if you entered exactly 25 words in the correct order.');
      }
      const a   = cleanAddr(ac.addr);
      const [em, ph] = await Promise.all([encryptMnemonic(seed, pw), hashPw(pw)]);
      await storageSet({ username: un, algoAddress: a, encryptedMnemonic: em, passwordHash: ph, pwHashVersion: 2 });
      window._sk   = ac.sk;
      window._addr = a;
      
      try {
        await bgMessage({
          type: 'SESSION_SET',
          sk:   Array.from(ac.sk),
          addr: a,
          duration: 'session'
        }, 6000);
      } catch (swErr) {
        console.warn('[Import] SW session set failed (ignored):', swErr.message);
      }
      ['import-username', 'import-password', 'import-seed'].forEach(id => $(id).value = '');
      showMainApp(un, a);
    } catch (e) {
      alert('❌ ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Restore account';
    }
  });

  ['username', 'password'].forEach(id => {
    $(id)?.addEventListener('keydown', e => { if (e.key === 'Enter') $('btn-create').click(); });
  });

  // ══════════════════════════════════════════════════════════════════
  // MAIN VIEW
  // ══════════════════════════════════════════════════════════════════

  async function showMainApp(username, address) {
    const a = cleanAddr(address);

    $('balance-display').textContent = '…';
    $('settings-username').textContent = username;
    $('settings-address').textContent  = shortAddr(a);
    $('settings-address').title        = a;
    $('settings-balance').textContent  = '…';

    const seedSection = $('seed-section');
    if (seedSection) seedSection.style.display = '';

    await loadContacts();
    await loadAutoLockSettings();
    refreshBalance();
    clearBadge();
    storageSet({ unreadCount: 0, bgUnreadCount: 0, lastOpenedTs: Date.now() });
    showView('view-main');
    startContactsPolling();
  }

  $('btn-open-conv').addEventListener('click', () => {
    const a = $('chat-recipient').value.trim();
    if (!isValidAlgoAddr(a)) { alert('Invalid Algorand address.'); return; }
    openChat(a);
  });
  $('chat-recipient').addEventListener('keydown', e => {
    if (e.key === 'Enter') $('btn-open-conv').click();
  });

  $('btn-go-settings').addEventListener('click', () => {
    refreshBalance();
    loadPinataSettings();
    applyFontSize(currentFontStep);
    syncAutoLockUI();
    showView('view-settings');
  });

  $('btn-manual-lock')?.addEventListener('click', async () => {
    stopPolling();
    await lockSession();
    showLockScreen();
  });

  // ── Donation / Support Handling in Modal Window ──────────────────────────────
  const DEV_DONATION_ADDR = 'RHSABLHWXLBBO6BRM6KKJL3M7TTVOYATFWOTITW7PMDTRFH6HEY2HKTMSA';

  $('btn-show-donation')?.addEventListener('click', () => {
    $('modal-donation').classList.add('open');
    try {
      generateQR(DEV_DONATION_ADDR, $('donation-qr-canvas'), 180);
    } catch (e) {
      console.warn('[Donation QR Error]', e);
    }
  });

  $('donation-modal-close')?.addEventListener('click', () => {
    $('modal-donation').classList.remove('open');
  });

  $('btn-copy-donation-addr')?.addEventListener('click', async () => {
    try { await navigator.clipboard.writeText(DEV_DONATION_ADDR); }
    catch {
      const t = document.createElement('textarea');
      t.value = DEV_DONATION_ADDR; document.body.appendChild(t); t.select();
      document.execCommand('copy'); document.body.removeChild(t);
    }
    const btn = $('btn-copy-donation-addr');
    const oldHtml = btn.innerHTML;
    btn.innerHTML = '<span class="material-icons" style="font-size: 14px;">done</span> Copied!';
    setTimeout(() => btn.innerHTML = oldHtml, 1500);
  });

  // ── Guide Modal Event Handlers ──
  const openGuide = () => {
    $('modal-guide')?.classList.add('open');
  };
  const closeGuide = () => {
    $('modal-guide')?.classList.remove('open');
  };
  $('topbar-logo')?.addEventListener('click', openGuide);
  $('lock-logo-btn')?.addEventListener('click', openGuide);
  $('guide-modal-close')?.addEventListener('click', closeGuide);
  $('btn-close-guide')?.addEventListener('click', closeGuide);

  // ══════════════════════════════════════════════════════════════════
  // SETTINGS VIEW
  // ══════════════════════════════════════════════════════════════════

  $('btn-settings-back').addEventListener('click', () => showView('view-main'));
  $('settings-address').addEventListener('click', copyMyAddress);
  $('btn-copy-addr-settings').addEventListener('click', copyMyAddress);

  async function copyMyAddress() {
    const a = $('settings-address').title;
    if (!a) return;
    try { await navigator.clipboard.writeText(a); }
    catch {
      const t = document.createElement('textarea');
      t.value = a; document.body.appendChild(t); t.select();
      document.execCommand('copy'); document.body.removeChild(t);
    }
    const el  = $('settings-address');
    const was = el.textContent;
    el.textContent = '✓ Copied';
    setTimeout(() => el.textContent = was, 1500);
  }

  $('btn-show-qr').addEventListener('click', () => {
    const a = $('settings-address').title;
    if (!a) return;
    showQrModal(a);
  });

  $('balance-display')?.addEventListener('click', () => {
    const a = $('settings-address').title;
    if (!a) return;
    showQrModal(a);
  });

  $('btn-show-seed').addEventListener('click', async () => {
    const sd = $('seed-display');
    if (sd.style.display === 'block') {
      sd.style.display = 'none';
      sd.textContent   = '';
      $('btn-show-seed').textContent = 'Show SEED';
      $('seed-confirm-password').value = '';
      return;
    }

    const pw = $('seed-confirm-password').value;
    if (!pw) { $('seed-confirm-password').focus(); return; }

    try {
      const s  = await storageGet(['encryptedMnemonic', 'passwordHash', 'pwHashVersion']);
      const h  = await hashPw(pw);
      if (s.pwHashVersion !== 2) {
        const hLegacy = await hashPwLegacy(pw);
        if (s.passwordHash !== hLegacy) throw new Error('Incorrect passcode');
      } else {
        if (s.passwordHash !== h) throw new Error('Incorrect passcode');
      }
      const mn = await decryptMnemonic(s.encryptedMnemonic, pw);
      sd.textContent   = mn;
      sd.style.display = 'block';
      $('btn-show-seed').textContent = 'Hide SEED';
    } catch { alert('❌ Incorrect passcode.'); }
  });

  $('seed-confirm-password').addEventListener('keydown', e => {
    if (e.key === 'Enter') $('btn-show-seed').click();
  });

  $('btn-logout').addEventListener('click', async () => {
    if (!confirm('Are you sure you want to log out and erase keys from local browser memory?')) return;
    stopPolling();
    await lockSession();
    chrome.storage.local.clear(() => {
      $('seed-display').style.display = 'none';
      $('seed-display').textContent   = '';
      $('btn-show-seed').textContent  = 'Show SEED';
      $('seed-confirm-password').value = '';
      contacts = [];
      clearBadge();
      showView('view-auth');
    });
  });

  // ══════════════════════════════════════════════════════════════════
  // CHAT & MESSAGE FLOW
  // ══════════════════════════════════════════════════════════════════

  $('btn-back').addEventListener('click', () => {
    stopPolling();
    clearPendingImage();
    currentConvAddr = null;
    showView('view-main');
    refreshBalance();
    clearBadge();
    storageSet({ unreadCount: 0, bgUnreadCount: 0 });
    startContactsPolling();
  });

  $('btn-unlock').addEventListener('click', async () => {
    const pw = $('unlock-password').value;
    if (!pw) { $('unlock-password').focus(); return; }
    const btn = $('btn-unlock');
    btn.disabled = true;
    btn.textContent = '⏳';
    try {
      await unlockSession(pw);
      $('unlock-password').value = '';
      showUnlockOrInput();
      if (currentConvAddr && !pollingTimer) {
        fetchConv(currentConvAddr);
        pollingTimer = setInterval(() => fetchConv(currentConvAddr), 8000);
      }
    } catch (e) {
      alert('❌ ' + e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = 'Unlock';
    }
  });
  $('unlock-password').addEventListener('keydown', e => {
    if (e.key === 'Enter') $('btn-unlock').click();
  });

  async function checkUnreadForContacts() {
    let myAddr = window._addr;
    if (!myAddr) {
      const s = await storageGet(['algoAddress']);
      myAddr = cleanAddr(s.algoAddress || '');
    }
    if (!myAddr || !contacts.length) return;

    const pfx = encodeURIComponent(btoa(MSG_PREFIX));

    try {
      const r = await fetch(
        `${INDEXER_NODE}/v2/transactions?address=${myAddr}&address-role=receiver&note-prefix=${pfx}&limit=100`
      );
      if (!r.ok) return;
      const data = await r.json();
      const txs  = data.transactions || [];

      const msgsByAddr = {};
      const allTxIds   = [];
      for (const tx of txs) {
        if (!tx.note) continue;
        let raw = '';
        try { raw = atob(tx.note); } catch { continue; }
        if (!raw.startsWith(MSG_PREFIX)) continue;
        const snd = cleanAddr(tx.sender || '');
        const rcv = cleanAddr(tx['payment-transaction']?.receiver || '');
        if (rcv !== myAddr) continue;
        if (!msgsByAddr[snd]) msgsByAddr[snd] = [];
        msgsByAddr[snd].push((tx['round-time'] || 0) * 1000);
        allTxIds.push(tx.id);
      }
      
      if (allTxIds.length) {
        const st = await storageGet(['seenTxIds']);
        const seen = new Set(st.seenTxIds || []);
        allTxIds.forEach(id => seen.add(id));
        await storageSet({ seenTxIds: [...seen].slice(-500) });
      }

      let changed = false;
      let totalUnread = 0;

      for (const c of contacts) {
        const theirAddr = c.address;
        const entry = unreadMap[theirAddr] || { count: 0, lastSeenTs: 0 };
        const msgs  = msgsByAddr[theirAddr] || [];

        const newCount = msgs.filter(ts => ts > entry.lastSeenTs).length;

        if (newCount !== entry.count) {
          unreadMap[theirAddr] = { count: newCount, lastSeenTs: entry.lastSeenTs };
          changed = true;
        }
        totalUnread += newCount;
      }

      if (changed) {
        saveUnreadMap();
        renderContacts();
      }
      setBadge(totalUnread);
    } catch (e) {
      console.warn('[ContactsPoll]', e.message);
    }
  }

  function startContactsPolling() {
    stopContactsPolling();
    checkUnreadForContacts();
    contactsPollingTimer = setInterval(checkUnreadForContacts, 12000);
  }

  function stopContactsPolling() {
    if (contactsPollingTimer) { clearInterval(contactsPollingTimer); contactsPollingTimer = null; }
  }

  fetchConv._prevLastSeenTs = {};

  async function updateAttachBtnVisibility() {
    const s = await storageGet(['pinataJwt', 'pinataGateway']);
    const configured = !!(s.pinataJwt && s.pinataGateway);
    const btn = $('btn-attach-img');
    if (btn) btn.style.display = configured ? '' : 'none';
  }

  async function openChat(theirAddr) {
    stopPolling();
    stopContactsPolling();
    renderedTxIds   = new Set();
    currentConvAddr = theirAddr;

    const prev = unreadMap[theirAddr] || { count: 0, lastSeenTs: 0 };
    fetchConv._prevLastSeenTs[theirAddr] = prev.lastSeenTs;

    unreadMap[theirAddr] = { count: 0, lastSeenTs: Date.now() };
    saveUnreadMap();

    const nick = getNick(theirAddr);
    const av   = makeAvatar(theirAddr, nick);

    $('conv-title').textContent = nick;
    const subtitleEl = document.querySelector('.chat-conv-status');
    if (subtitleEl) {
      const c = contacts.find(x => cleanAddr(x.address) === cleanAddr(theirAddr));
      const note = c ? c.note : '';
      subtitleEl.innerHTML = `<span class="enc-dot"></span> E2E · Algorand Mainnet${note ? ` · <span style="color:var(--acc); font-weight:600;">${esc(note)}</span>` : ''}`;
    }
    const avi = $('conv-avatar');
    avi.textContent      = av.letter;
    avi.style.background = av.bg;
    avi.style.color      = av.color;

    $('chat-window').innerHTML = `
      <div class="chat-ph">
        <span class="material-icons">hourglass_empty</span>
        Loading messages…
      </div>`;

    const deletedTs = await getConvDeletedTs(theirAddr);
    $('conv-deleted-notice').style.display = deletedTs ? 'flex' : 'none';

    showUnlockOrInput();
    showView('view-chat');
    updateAttachBtnVisibility();

    _userIsScrolledUp = false;
    _pendingNewMsgIds = [];
    hideNewMsgBubble();

    fetchConv(theirAddr);
    pollingTimer = setInterval(() => fetchConv(theirAddr), 8000);
  }

  function stopPolling() {
    if (pollingTimer) { clearInterval(pollingTimer); pollingTimer = null; }
  }

  // ── Scroll & New messages bubble ──────────────────────────────────────────
  const SCROLL_THRESHOLD = 80;

  (function initScrollTracking() {
    const win = $('chat-window');
    if (!win) return;
    win.addEventListener('scroll', () => {
      const distFromBottom = win.scrollHeight - win.scrollTop - win.clientHeight;
      _userIsScrolledUp = distFromBottom > SCROLL_THRESHOLD;
      if (!_userIsScrolledUp && _pendingNewMsgIds.length > 0) {
        _pendingNewMsgIds = [];
        hideNewMsgBubble();
      }
    }, { passive: true });
  })();

  function showNewMsgBubble(count) {
    let bubble = $('new-msg-bubble');
    if (!bubble) return;
    bubble.textContent = count === 1
      ? '↓ 1 new message'
      : `↓ ${count} new messages`;
    bubble.classList.add('visible');
  }

  function hideNewMsgBubble() {
    const bubble = $('new-msg-bubble');
    if (bubble) bubble.classList.remove('visible');
  }

  (function initBubbleClick() {
    const bubble = $('new-msg-bubble');
    if (!bubble) return;
    bubble.addEventListener('click', () => {
      const win = $('chat-window');
      if (_pendingNewMsgIds.length > 0) {
        const firstId = _pendingNewMsgIds[0];
        const el = win.querySelector(`[data-txid="${firstId}"]`);
        if (el) {
          el.scrollIntoView({ behavior: 'smooth', block: 'start' });
        } else {
          win.scrollTo({ top: win.scrollHeight, behavior: 'smooth' });
        }
      } else {
        win.scrollTo({ top: win.scrollHeight, behavior: 'smooth' });
      }
      _pendingNewMsgIds = [];
      hideNewMsgBubble();
    });
  })();

  // ── Message Fetching ──────────────────────────────────────────────────────

  async function fetchConv(theirAddr) {
    let myAddr = window._addr;
    if (!myAddr) {
      const s = await storageGet(['algoAddress']);
      myAddr = cleanAddr(s.algoAddress || '');
    }
    if (!myAddr) return;

    const deletedTs = await getConvDeletedTs(theirAddr);
    const prevLastSeenTs = fetchConv._prevLastSeenTs[theirAddr] || 0;

    try {
      const pfx = encodeURIComponent(btoa(MSG_PREFIX));
      const [rOut, rIn] = await Promise.all([
        fetch(`${INDEXER_NODE}/v2/transactions?address=${myAddr}&address-role=sender&note-prefix=${pfx}&limit=100`),
        fetch(`${INDEXER_NODE}/v2/transactions?address=${myAddr}&address-role=receiver&note-prefix=${pfx}&limit=100`)
      ]);
      if (!rOut.ok || !rIn.ok) return;
      const [dOut, dIn] = await Promise.all([rOut.json(), rIn.json()]);

      const all = [
        ...(dOut.transactions || []).map(t => ({ ...t, _dir: 'sent' })),
        ...(dIn.transactions  || []).map(t => ({ ...t, _dir: 'received' }))
      ].filter(tx => {
        const snd = cleanAddr(tx.sender || '');
        const rcv = cleanAddr(tx['payment-transaction']?.receiver || '');
        return tx._dir === 'sent'
          ? snd === myAddr     && rcv === theirAddr
          : snd === theirAddr  && rcv === myAddr;
      }).sort((a, b) => (a['round-time'] || 0) - (b['round-time'] || 0));

      const win = $('chat-window');
      const ph  = win.querySelector('.chat-ph');

      let newMsgCount = 0;

      for (const tx of all) {
        if (renderedTxIds.has(tx.id) || !tx.note) continue;

        const txMs = (tx['round-time'] || 0) * 1000;
        if (deletedTs && txMs < deletedTs) continue;

        let raw = '';
        try { raw = atob(tx.note); } catch { continue; }
        if (!raw.startsWith(MSG_PREFIX)) continue;
        let text = '';
        try { text = await decryptMsg(raw.slice(MSG_PREFIX.length), myAddr, theirAddr); }
        catch { continue; }
        if (ph) ph.remove();
        appendMsg(tx._dir, text, tx.id, tx['round-time']);

        if (tx._dir === 'received') {
          if (txMs > prevLastSeenTs) {
            newMsgCount++;
          }
        }
      }

      if (newMsgCount > 0) {
        const entry = unreadMap[theirAddr] || { count: 0, lastSeenTs: 0 };
        unreadMap[theirAddr] = { count: entry.count + newMsgCount, lastSeenTs: entry.lastSeenTs };
        saveUnreadMap();
        renderContacts();
        const s = await storageGet(['unreadCount']);
        const total = (s.unreadCount || 0) + newMsgCount;
        await storageSet({ unreadCount: total });
        setBadge(total);
      }

      const remaining = win.querySelector('.chat-ph');
      if (remaining) remaining.innerHTML = `
        <span class="material-icons">mail_outline</span>
        No messages yet. Send something!`;

      if (!_userIsScrolledUp) {
        win.scrollTop = win.scrollHeight;
      }
    } catch (e) { console.warn('Fetch:', e.message); }
  }

  // ── Render Message ────────────────────────────────────────────────────────

  function appendMsg(dir, text, txId, roundTime) {
    renderedTxIds.add(txId);
    const win  = $('chat-window');
    const time = roundTime
      ? new Date(roundTime * 1000).toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' })
      : new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });

    const author = dir === 'sent' ? 'You' : esc(getNick(currentConvAddr));

    const div = document.createElement('div');
    div.className = 'msg ' + dir;
    div.setAttribute('data-txid', txId);

    let contentHtml;
    if (text.startsWith('APIMGENC:')) {
      const rawImgUrl = text.slice(9);
      if (/^https:\/\//i.test(rawImgUrl)) {
        const placeholderId = 'imgph_' + Math.random().toString(36).slice(2);
        contentHtml = `<div id="${placeholderId}" class="msg-img-placeholder">🔒 Decrypting image…</div>`;
        
        setTimeout(async () => {
          const ph = document.getElementById(placeholderId);
          if (!ph) return;
          let myAddr = window._addr;
          if (!myAddr) {
            const sd = await storageGet(['algoAddress']);
            myAddr = cleanAddr(sd.algoAddress || '');
          }
          try {
            const objectUrl = await fetchAndDecryptImg(rawImgUrl, myAddr, currentConvAddr);
            const img = document.createElement('img');
            img.className = 'msg-img';
            img.src = objectUrl;
            img.alt = 'Image';
            img.loading = 'lazy';
            img.onerror = () => { img.alt = 'Loading error'; };
            img.addEventListener('click', () => {
              chrome.tabs.create({ url: objectUrl });
            });
            ph.replaceWith(img);
          } catch (e) {
            ph.textContent = '❌ Failed to decrypt image: ' + e.message;
            ph.style.color = 'var(--red)';
          }
        }, 0);
      } else {
        contentHtml = `<div class="msg-text" style="color:var(--red);">Image blocked (unallowed URL).</div>`;
      }
    } else if (text.startsWith('APIMG:')) {
      const rawImgUrl = text.slice(6);
      if (/^https:\/\//i.test(rawImgUrl)) {
        const imgUrl = esc(rawImgUrl);
        contentHtml = `<img class="msg-img" src="${imgUrl}" alt="Image" loading="lazy"
          onerror="this.alt='❌ Image loading error';this.style.display='inline-block';this.style.padding='8px';this.style.fontSize='11px';">`;
      } else {
        contentHtml = `<div class="msg-text" style="color:var(--red);">Image blocked (unallowed URL).</div>`;
      }
    } else {
      contentHtml = `<div class="msg-text">${esc(text)}</div>`;
    }

    div.innerHTML = `
      <div class="msg-author">${author}</div>
      ${contentHtml}
      <div class="msg-time">${time}</div>
    `;

    const imgEl = div.querySelector('.msg-img');
    if (imgEl && text.startsWith('APIMG:')) {
      imgEl.addEventListener('click', () => {
        const rawUrl = text.slice(6);
        if (/^https:\/\//i.test(rawUrl)) {
          chrome.tabs.create({ url: rawUrl });
        }
      });
    }

    win.appendChild(div);

    if (_userIsScrolledUp && dir === 'received') {
      _pendingNewMsgIds.push(txId);
      showNewMsgBubble(_pendingNewMsgIds.length);
    } else {
      win.scrollTop = win.scrollHeight;
    }

    return div;
  }

  // ── Send Message ──────────────────────────────────────────────────────────

  $('btn-send').addEventListener('click', sendMessage);
  $('chat-message').addEventListener('keydown', e => {
    if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); sendMessage(); }
  });

  async function sendMessage() {
    const btn = $('btn-send');
    if (btn && btn.disabled) return;

    if (_pendingImageBlob) { await sendImageMessage(); return; }

    const theirAddr = currentConvAddr;
    const text      = ($('chat-message').value || '').trim();
    if (!text) return;
    if (!theirAddr || theirAddr.length !== 58) return;
    if (!isUnlocked()) { showUnlockOrInput(); return; }

    if (!window._sk) {
      alert('⚠️ Private key missing.\nTo send encrypted messages, please import your full account seed directly.');
      return;
    }

    const myAddr = cleanAddr(window._addr);
    if (!myAddr || myAddr.length !== 58) {
      alert('❌ Session expired - please unlock your account again.');
      await lockSession();
      showUnlockOrInput();
      return;
    }

    const tempTxId = 'temp_' + Date.now() + '_' + Math.random().toString(36).slice(2);

    // Clear message and focus immediately
    $('chat-message').value = '';
    $('chat-message').focus();
    $('chat-window').querySelector('.chat-ph')?.remove();

    // Append immediately as temporary
    const msgDiv = appendMsg('sent', text, tempTxId, null);
    if (msgDiv) {
      msgDiv.classList.add('pending');
      const timeEl = msgDiv.querySelector('.msg-time');
      if (timeEl) {
        timeEl.innerHTML = `<span class="material-icons rotating-icon" style="font-size:10px; color:var(--amber); vertical-align: middle; margin-right: 3px;">sync</span>Sending...`;
      }
    }

    // Temporarily throttle send button briefly to prevent double clicks
    if (btn) {
      btn.disabled = true;
      setTimeout(() => { if (btn) btn.disabled = false; }, 150);
    }

    // Send transaction asynchronously in the background
    (async () => {
      try {
        const encrypted = await encryptMsg(text, myAddr, theirAddr);
        const noteBytes  = new TextEncoder().encode(encrypted);
        if (noteBytes.length > 1024) {
          throw new Error('Message too long (max ~700 characters encrypted).');
        }

        const client = new algosdk.Algodv2('', ALGOD_NODE, '');
        const params = await client.getTransactionParams().do();

        const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
          sender:   myAddr,
          receiver: theirAddr,
          amount: 0,
          note: noteBytes,
          suggestedParams: params
        });

        const signed = txn.signTxn(window._sk);
        const res    = await client.sendRawTransaction(signed).do();

        const txid = res.txid || res.txId || res['tx-id'] || '';
        if (txid) {
          await algosdk.waitForConfirmation(client, txid, 4);
        }

        if (msgDiv) {
          msgDiv.classList.remove('pending');
          msgDiv.setAttribute('data-txid', txid);
          const timeEl = msgDiv.querySelector('.msg-time');
          if (timeEl) {
            timeEl.textContent = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });
          }
          renderedTxIds.add(txid);
        }

        refreshBalance();

        if (unlockDuration === 'once') {
          lockSession();
          showUnlockOrInput();
        }
      } catch (e) {
        console.error('Background send error:', e);
        if (msgDiv) {
          msgDiv.classList.remove('pending');
          msgDiv.classList.add('error');
          const timeEl = msgDiv.querySelector('.msg-time');
          if (timeEl) {
            timeEl.innerHTML = `<span style="color:var(--red); font-weight:500; display:flex; align-items:center; gap:3px;"><span class="material-icons" style="font-size:11px;">error_outline</span> Failed to send</span>`;
          }
        }
      }
    })();
  }

  // ── Emoji Picker ──────────────────────────────────────────────────────────

  const EMOJIS = [
    '😀','😂','😍','😎','🥰','😅','😭','😡',
    '👍','👎','👏','🙏','🤝','💪','✌️','🤞',
    '❤️','💙','💚','💛','🧡','💜','🖤','🤍',
    '🎉','🔥','⚡','💯','✅','❌','⚠️','🔐',
    '🍕','🍺','☕','🎮','🏆','🚀','💰','🌙'
  ];

  (function initEmojiPicker() {
    const picker = $('emoji-picker');
    EMOJIS.forEach(em => {
      const item = document.createElement('div');
      item.className = 'emoji-item';
      item.textContent = em;
      item.addEventListener('click', () => {
        const inp = $('chat-message');
        const pos = inp.selectionStart || inp.value.length;
        inp.value = inp.value.slice(0, pos) + em + inp.value.slice(pos);
        inp.focus();
        inp.selectionStart = inp.selectionEnd = pos + em.length;
        picker.classList.remove('open');
      });
      picker.appendChild(item);
    });
  })();

  $('btn-emoji').addEventListener('click', (e) => {
    e.stopPropagation();
    $('emoji-picker').classList.toggle('open');
  });

  document.addEventListener('click', (e) => {
    if (!e.target.closest('#emoji-picker') && !e.target.closest('#btn-emoji')) {
      $('emoji-picker')?.classList.remove('open');
    }
  });

  // ── Font Size Control ─────────────────────────────────────────────────────

  const FONT_BASE  = 14.5;
  const FONT_STEP  = 1;
  const FONT_STEPS = 5;
  let currentFontStep = 0;

  function applyFontSize(step) {
    currentFontStep = Math.max(0, Math.min(FONT_STEPS - 1, step));
    const size = FONT_BASE + currentFontStep * FONT_STEP;
    document.documentElement.style.setProperty('--chat-font-size', size + 'px');

    const display = $('font-size-display');
    if (display) display.textContent = size % 1 === 0 ? size.toFixed(0) : size.toFixed(1);

    document.querySelectorAll('.font-size-step').forEach(dot => {
      const s = parseInt(dot.dataset.step);
      dot.classList.toggle('active', s <= currentFontStep);
    });

    const dec = $('btn-font-dec');
    const inc = $('btn-font-inc');
    if (dec) dec.disabled = currentFontStep === 0;
    if (inc) inc.disabled = currentFontStep === FONT_STEPS - 1;
  }

  async function loadFontSize() {
    const s = await storageGet(['chatFontStep']);
    const step = typeof s.chatFontStep === 'number' ? s.chatFontStep : 0;
    applyFontSize(step);
  }

  async function saveFontSize(step) {
    applyFontSize(step);
    await storageSet({ chatFontStep: step });
  }

  $('btn-font-dec').addEventListener('click', () => saveFontSize(currentFontStep - 1));
  $('btn-font-inc').addEventListener('click', () => saveFontSize(currentFontStep + 1));

  document.querySelectorAll('.font-size-step').forEach(dot => {
    dot.addEventListener('click', () => saveFontSize(parseInt(dot.dataset.step)));
  });

  loadFontSize();

  // ── Pinata Gateway & JWT ──────────────────────────────────────────────────

  async function loadPinataSettings() {
    const s = await storageGet(['pinataJwt', 'pinataGateway']);
    if (s.pinataJwt)     $('pinata-jwt').value     = s.pinataJwt;
    if (s.pinataGateway) $('pinata-gateway').value = s.pinataGateway;
  }

  $('btn-pinata-save').addEventListener('click', async () => {
    const jwt = $('pinata-jwt').value.trim();
    const gw  = $('pinata-gateway').value.trim();
    if (!jwt || !gw) { setPinataStatus('⚠️ Please fill in both fields.', 'amber'); return; }
    if (!/^https:\/\/[^\s]+$/.test(gw)) {
      setPinataStatus('⚠️ Gateway must be a valid HTTPS address.', 'amber'); return;
    }
    await storageSet({ pinataJwt: jwt, pinataGateway: gw.replace(/\/$/, '') });
    setPinataStatus('✅ Saved!', 'green');
    updateAttachBtnVisibility();
    setTimeout(() => setPinataStatus('', ''), 2500);
  });

  $('btn-pinata-test').addEventListener('click', async () => {
    const s = await storageGet(['pinataJwt']);
    if (!s.pinataJwt) { setPinataStatus('⚠️ Please save your configuration first.', 'amber'); return; }
    setPinataStatus('⏳ Testing connection…', 'txt2');
    try {
      const r = await fetch('https://api.pinata.cloud/data/testAuthentication', {
        headers: { Authorization: 'Bearer ' + s.pinataJwt }
      });
      if (r.ok) {
        setPinataStatus('✅ Connection OK! Pinata is ready.', 'green');
      } else {
        const d = await r.json().catch(() => ({}));
        setPinataStatus('❌ Error: ' + (d.error?.reason || r.status), 'red');
      }
    } catch (e) {
      setPinataStatus('❌ Connection failed: ' + e.message, 'red');
    }
  });

  $('link-pinata-signup').addEventListener('click', e => {
    e.preventDefault();
    chrome.tabs.create({ url: 'https://www.pinata.cloud' });
  });

  function setPinataStatus(msg, color) {
    const el = $('pinata-status');
    if (!el) return;
    el.textContent = msg;
    el.style.color = color === 'green' ? 'var(--green)'
                   : color === 'red'   ? 'var(--red)'
                   : color === 'amber' ? 'var(--amber)'
                   : 'var(--txt2)';
  }

  // ══════════════════════════════════════════════════════════════════
  // IMAGE ATTACHMENTS & E2E ENCRYPTION
  // ══════════════════════════════════════════════════════════════════

  const IMG_MSG_PREFIX_ENC = 'APIMGENC:';
  let _pendingImageBlob = null;

  function resizeImageToBlob(file) {
    return new Promise((resolve, reject) => {
      const img = new Image();
      const url = URL.createObjectURL(file);
      img.onload = () => {
        URL.revokeObjectURL(url);
        const MAX = 1024;
        let { width: w, height: h } = img;
        if (w > MAX || h > MAX) {
          if (w >= h) { h = Math.round(h * MAX / w); w = MAX; }
          else        { w = Math.round(w * MAX / h); h = MAX; }
        }
        const canvas = document.createElement('canvas');
        canvas.width  = w;
        canvas.height = h;
        const ctx = canvas.getContext('2d');
        ctx.drawImage(img, 0, 0, w, h);
        canvas.toBlob(blob => blob ? resolve({ blob, w, h }) : reject(new Error('Image conversion failed')),
          'image/jpeg', 0.82);
      };
      img.onerror = () => { URL.revokeObjectURL(url); reject(new Error('Image load error')); };
      img.src = url;
    });
  }

  async function encryptBlob(blob, myAddr, theirAddr) {
    const key = await deriveMsgKey(myAddr, theirAddr);
    const iv  = crypto.getRandomValues(new Uint8Array(12));
    const ct  = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, await blob.arrayBuffer());
    const out = new Uint8Array(12 + ct.byteLength);
    out.set(iv, 0);
    out.set(new Uint8Array(ct), 12);
    return new Blob([out], { type: 'application/octet-stream' });
  }

  async function fetchAndDecryptImg(url, myAddr, theirAddr) {
    const r = await fetch(url);
    if (!r.ok) throw new Error('Cannot fetch image (HTTP ' + r.status + ')');
    const key = await deriveMsgKey(myAddr, theirAddr);
    const raw = new Uint8Array(await r.arrayBuffer());
    const pt  = await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv: raw.slice(0, 12) }, key, raw.slice(12)
    );
    return URL.createObjectURL(new Blob([pt], { type: 'image/jpeg' }));
  }

  async function uploadToPinata(blob, filename) {
    const s = await storageGet(['pinataJwt', 'pinataGateway']);
    if (!s.pinataJwt || !s.pinataGateway) {
      throw new Error('Missing Pinata configuration — please set it in Settings → Pinata IPFS.');
    }
    const form = new FormData();
    form.append('file', blob, filename || 'image.jpg');
    const r = await fetch('https://api.pinata.cloud/pinning/pinFileToIPFS', {
      method:  'POST',
      headers: { Authorization: 'Bearer ' + s.pinataJwt },
      body:    form
    });
    if (!r.ok) {
      const d = await r.json().catch(() => ({}));
      throw new Error('Pinata: ' + (d.error?.reason || r.status));
    }
    const data = await r.json();
    const cid  = data.IpfsHash;
    return s.pinataGateway + '/ipfs/' + cid;
  }

  $('btn-attach-img').addEventListener('click', () => {
    if (!isUnlocked()) { showUnlockOrInput(); return; }
    $('img-file-input').value = '';
    $('img-file-input').click();
  });

  $('img-file-input').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const btn = $('btn-attach-img');
    btn.classList.add('uploading');
    btn.innerHTML = `<span class="material-icons rotating-icon">sync</span>`;

    try {
      const { blob, w, h } = await resizeImageToBlob(file);
      _pendingImageBlob = blob;

      const previewUrl = URL.createObjectURL(blob);
      $('img-preview-thumb').src = previewUrl;
      const kb = (blob.size / 1024).toFixed(0);
      $('img-preview-info').textContent = `${w}×${h}px · ${kb} KB · JPEG`;
      $('img-preview-strip').classList.add('on');

      btn.innerHTML = `<span class="material-icons" style="color: var(--green);">image</span>`;
      btn.classList.remove('uploading');
      btn.style.borderColor = 'var(--green)';
      btn.style.color       = 'var(--green)';
    } catch (err) {
      _pendingImageBlob = null;
      btn.classList.remove('uploading');
      btn.innerHTML = `<span class="material-icons">attach_file</span>`;
      btn.style.borderColor = '';
      btn.style.color       = '';
      alert('❌ ' + err.message);
    }
  });

  $('btn-img-preview-clear').addEventListener('click', clearPendingImage);

  function clearPendingImage() {
    _pendingImageBlob = null;
    $('img-preview-strip').classList.remove('on');
    const thumb = $('img-preview-thumb');
    if (thumb.src) URL.revokeObjectURL(thumb.src);
    thumb.src = '';
    const btn = $('btn-attach-img');
    btn.innerHTML = `<span class="material-icons">attach_file</span>`;
    btn.style.borderColor = '';
    btn.style.color       = '';
  }

  async function sendImageMessage() {
    const theirAddr = currentConvAddr;
    if (!theirAddr || theirAddr.length !== 58) return;
    if (!isUnlocked()) { showUnlockOrInput(); return; }
    if (!window._sk) {
      alert('⚠️ Read-only accounts cannot send images.');
      return;
    }
    if (!_pendingImageBlob) return;

    const myAddr = cleanAddr(window._addr);
    if (!myAddr || myAddr.length !== 58) {
      alert('❌ Session expired - please unlock your account again.');
      await lockSession();
      showUnlockOrInput();
      return;
    }

    const btn = $('btn-send');
    const attachBtn = $('btn-attach-img');
    const bnr = $('sending-banner');
    const bnrText = $('sending-banner-text');

    btn.disabled = true;
    btn.innerHTML = `<span class="material-icons rotating-icon" style="color: var(--amber);">sync</span>`;
    attachBtn.classList.add('uploading');
    attachBtn.innerHTML = `<span class="material-icons rotating-icon">cloud_upload</span>`;

    if (bnr) bnr.style.display = 'flex';
    if (bnrText) bnrText.innerHTML = `<strong>IPFS UPLOAD & TRANSACTION IN PROGRESS</strong><br>Encrypting, uploading to IPFS and sending... <strong>DO NOT CLOSE POPUP!</strong>`;

    try {
      const encryptedBlob = await encryptBlob(_pendingImageBlob, myAddr, theirAddr);
      const ts  = Date.now();
      const url = await uploadToPinata(encryptedBlob, `ap_${ts}.bin`);

      const payload   = IMG_MSG_PREFIX_ENC + url;
      const encrypted = await encryptMsg(payload, myAddr, theirAddr);
      const noteBytes = new TextEncoder().encode(encrypted);

      if (noteBytes.length > 1024) {
        alert('IPFS gateway URL is too long (shorten the gateway address in Settings).');
        if (bnr) bnr.style.display = 'none';
        return;
      }

      const client = new algosdk.Algodv2('', ALGOD_NODE, '');
      const params = await client.getTransactionParams().do();
      const txn = algosdk.makePaymentTxnWithSuggestedParamsFromObject({
        sender:          myAddr,
        receiver:        theirAddr,
        amount:          0,
        note:            noteBytes,
        suggestedParams: params
      });
      const signed = txn.signTxn(window._sk);
      const res    = await client.sendRawTransaction(signed).do();
      const txid   = res.txid || res.txId || res['tx-id'] || '';
      if (txid) await algosdk.waitForConfirmation(client, txid, 4);

      refreshBalance();
      $('chat-window').querySelector('.chat-ph')?.remove();
      appendMsg('sent', payload, txid, null);
      clearPendingImage();
      $('chat-message').focus();

      if (unlockDuration === 'once') { lockSession(); showUnlockOrInput(); }

    } catch (e) {
      console.error(e);
      alert('❌ Image sending error: ' + e.message);
    } finally {
      btn.disabled = false;
      btn.innerHTML = `<span class="material-icons">send</span>`;
      attachBtn.classList.remove('uploading');
      attachBtn.innerHTML = _pendingImageBlob ? `<span class="material-icons" style="color: var(--green);">image</span>` : `<span class="material-icons">attach_file</span>`;
      if (bnr) {
        bnr.style.display = 'none';
        if (bnrText) bnrText.innerHTML = `<strong>TRANSACTION IN PROGRESS</strong><br>Sending securely... <strong>DO NOT CLOSE POPUP!</strong>`;
      }
    }
  }

  // ══════════════════════════════════════════════════════════════════
  // QR CODE GENERATOR (NATIVE)
  // ══════════════════════════════════════════════════════════════════

  function showQrModal(address) {
    $('qr-address-display').textContent = address;
    generateQR(address, $('qr-canvas'), 200);
    $('modal-qr').classList.add('open');
  }

  $('qr-modal-close').addEventListener('click', () => $('modal-qr').classList.remove('open'));
  $('modal-qr').addEventListener('click', e => {
    if (e.target === $('modal-qr')) $('modal-qr').classList.remove('open');
  });

  $('btn-copy-qr-addr').addEventListener('click', async () => {
    const a = $('qr-address-display').textContent;
    try { await navigator.clipboard.writeText(a); }
    catch { const t = document.createElement('textarea'); t.value = a; document.body.appendChild(t); t.select(); document.execCommand('copy'); document.body.removeChild(t); }
    $('btn-copy-qr-addr').textContent = '✓ Copied!';
    setTimeout(() => ($('btn-copy-qr-addr').textContent = '📋 Copy address'), 1500);
  });

  function generateQR(text, canvas, size) {
    const ctx = canvas.getContext('2d');
    canvas.width  = size;
    canvas.height = size;
    ctx.fillStyle = '#ffffff';
    ctx.fillRect(0, 0, size, size);

    try {
      const qr   = new QRCodeRaw({ content: text, ecl: 'M' });
      const mods = qr.modules();
      const n    = mods.length;
      const margin = 4;
      const cell   = size / (n + margin * 2);
      const off    = margin * cell;

      ctx.fillStyle = '#000000';
      for (let r = 0; r < n; r++) {
        for (let c = 0; c < n; c++) {
          if (mods[r][c]) {
            ctx.fillRect(
              Math.floor(off + c * cell),
              Math.floor(off + r * cell),
              Math.ceil(cell),
              Math.ceil(cell)
            );
          }
        }
      }
    } catch (e) {
      ctx.fillStyle = '#0a0b0f';
      ctx.fillRect(0, 0, size, size);
      ctx.fillStyle = '#e57373';
      ctx.font      = '11px monospace';
      ctx.textAlign = 'center';
      ctx.fillText('QR generation error', size / 2, size / 2 - 8);
      ctx.fillText(String(e.message).slice(0, 40), size / 2, size / 2 + 12);
      console.error('[QR] generateQR error:', e);
    }
  }

});
