/* Complaints Tracker - Vanilla JS, local-first JSON store */
(function () {
  "use strict";

  // Utilities
  const qs = (sel, el = document) => el.querySelector(sel);
  const qsa = (sel, el = document) => Array.from(el.querySelectorAll(sel));
  const fmtDate = (iso) => (iso ? new Date(iso).toLocaleDateString() : "");
  const downloadBlob = (dataStr, filename, type = "application/json") => {
    const blob = new Blob([dataStr], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url; a.download = filename; a.click();
    setTimeout(() => URL.revokeObjectURL(url), 500);
  };

  function arrayBufferToBase64(buffer) {
    const bytes = new Uint8Array(buffer);
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return btoa(binary);
  }

  async function loadInstitutions() {
    try {
      const res = await fetch('data/institutions.csv');
      if (!res.ok) return [];
      const text = await res.text();
      const lines = text.split(/\r?\n/).filter(Boolean);
      const header = lines.shift();
      const rows = lines.map(l => {
        const parts = l.split(/,(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)/); // split on commas outside quotes
        return { name: parts[0], address: parts[1]?.replace(/^\"|\"$/g, ''), email: parts[2] };
      }).filter(r => r.name);
      return rows;
    } catch { return []; }
  }

  const STORAGE_KEYS = {
    complaints: "complaintsTracker.complaints.v1",
    sars: "complaintsTracker.sars.v1",
    phso: "complaintsTracker.phso.v1",
    legal: "complaintsTracker.legal.v1",
    accountability: "complaintsTracker.accountability.v1",
    users: "complaintsTracker.users.v1",
    session: "complaintsTracker.session.v1",
    theme: "complaintsTracker.theme.v1",
  };

  const Server = {
    baseUrl: (function(){
      const url = new URL(window.location.href);
      const qp = url.searchParams.get('api');
      const ls = localStorage.getItem('complaintsTracker.apiBase');
      const meta = document.querySelector('meta[name="api-base"]');
      return qp || ls || (meta && meta.getAttribute('content')) || 'http://localhost:8000';
    })(),
    token: null,
    isOn() { return !!this.token; }
  };

  const isServerMode = () => {
    const el = qs('#serverModeToggle');
    return !!(el && el.checked && Server.token);
  };

  async function serverFetch(path, options = {}) {
    const headers = options.headers ? { ...options.headers } : {};
    if (Server.token) headers['Authorization'] = `Bearer ${Server.token}`;
    return fetch(`${Server.baseUrl}${path}`, { ...options, headers });
  }

  // Simple crypto gate (not strong encryption, optional)
  async function deriveKeyFromPassword(password) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      { name: "PBKDF2" },
      false,
      ["deriveKey"]
    );
    return crypto.subtle.deriveKey(
      { name: "PBKDF2", salt: enc.encode("complaints-tracker-salt"), iterations: 150000, hash: "SHA-256" },
      keyMaterial,
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptText(plaintext, password) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const key = await deriveKeyFromPassword(password);
    const enc = new TextEncoder();
    const ciphertext = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, enc.encode(plaintext));
    const out = {
      iv: Array.from(iv),
      data: Array.from(new Uint8Array(ciphertext))
    };
    return btoa(JSON.stringify(out));
  }

  async function decryptText(cipherB64, password) {
    const decoded = JSON.parse(atob(cipherB64));
    const iv = new Uint8Array(decoded.iv);
    const data = new Uint8Array(decoded.data);
    const key = await deriveKeyFromPassword(password);
    const plainBuf = await crypto.subtle.decrypt({ name: "AES-GCM", iv }, key, data);
    return new TextDecoder().decode(plainBuf);
  }

  // Audit trail: tamper-evident hash chain for history entries
  async function sha256Hex(input) {
    const enc = new TextEncoder();
    const buf = await crypto.subtle.digest("SHA-256", enc.encode(input));
    return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, "0")).join("");
  }

  async function appendHistory(complaint, eventText) {
    const date = new Date().toISOString().slice(0, 10);
    const prevHash = (complaint.history && complaint.history.length) ? (complaint.history[complaint.history.length - 1].hash || "") : "";
    const hash = await sha256Hex(`${prevHash}|${date}|${eventText}`);
    complaint.history = complaint.history || [];
    complaint.history.push({ date, event: eventText, hash });
  }

  async function verifyHistoryChain(complaint) {
    const hist = complaint.history || [];
    let prev = "";
    for (const h of hist) {
      const expected = await sha256Hex(`${prev}|${h.date}|${h.event}`);
      if (h.hash !== expected) return false;
      prev = h.hash;
    }
    return true;
  }

  // Data layer
  const Data = {
    complaints: [],
    sars: [],
    phsoCases: [],
    legalCases: [],
    accountability: [],
    users: [],
    session: { user: null },
    idb: null,
    key(nameConst) {
      const user = (this.session && this.session.user && this.session.user.username) ? this.session.user.username : 'public';
      return `${nameConst}:${user}`;
    },
    async init() {
      // Load from localStorage, fallback to bundled JSON
      const lsSession = localStorage.getItem(STORAGE_KEYS.session);
      const lsUsers = localStorage.getItem(STORAGE_KEYS.users);
      if (lsUsers) { try { this.users = JSON.parse(lsUsers); } catch { this.users = []; } }
      this.session = lsSession ? JSON.parse(lsSession) : { user: null };
      // default user seeding
      try {
        if (!this.users.find(u => u.username === 'AAAPPP')) {
          this.users.push({ username: 'AAAPPP', password: 'AAA123', createdAt: new Date().toISOString() });
        }
      } catch {}
      const lsComplaints = localStorage.getItem(this.key(STORAGE_KEYS.complaints));
      const lsSars = localStorage.getItem(this.key(STORAGE_KEYS.sars));
      const lsPhso = localStorage.getItem(this.key(STORAGE_KEYS.phso));
      const lsLegal = localStorage.getItem(this.key(STORAGE_KEYS.legal));
      const lsAcc = localStorage.getItem(this.key(STORAGE_KEYS.accountability));
      if (lsComplaints && lsSars) {
        try {
          this.complaints = JSON.parse(lsComplaints);
          this.sars = JSON.parse(lsSars);
          this.phsoCases = lsPhso ? JSON.parse(lsPhso) : [];
          this.legalCases = lsLegal ? JSON.parse(lsLegal) : [];
          this.accountability = lsAcc ? JSON.parse(lsAcc) : [];
        } catch {
          await this._loadFromFiles();
        }
      } else {
        await this._loadFromFiles();
      }
      // Backfill audit hashes for existing history entries lacking hashes
      try {
        for (const c of this.complaints) {
          const hist = Array.isArray(c.history) ? c.history : [];
          let prev = "";
          let mutated = false;
          for (const h of hist) {
            const expected = await sha256Hex(`${prev}|${h.date}|${h.event}`);
            if (!h.hash || h.hash !== expected) {
              h.hash = expected;
              mutated = true;
            }
            prev = h.hash;
          }
          if (mutated) {
            // ensure the complaint record is saved with updated hashes
            // (upsert will call save later)
          }
        }
      } catch {}
      await this._openIdb();
      this.save();
      // Post-init sync if server mode already enabled
      try {
        if (isServerMode()) await this.syncFromServer();
      } catch {}
    },
    reloadForCurrentUser() {
      try {
        const lsC = localStorage.getItem(this.key(STORAGE_KEYS.complaints));
        const lsS = localStorage.getItem(this.key(STORAGE_KEYS.sars));
        const lsP = localStorage.getItem(this.key(STORAGE_KEYS.phso));
        const lsL = localStorage.getItem(this.key(STORAGE_KEYS.legal));
        const lsA = localStorage.getItem(this.key(STORAGE_KEYS.accountability));
        this.complaints = lsC ? JSON.parse(lsC) : [];
        this.sars = lsS ? JSON.parse(lsS) : [];
        this.phsoCases = lsP ? JSON.parse(lsP) : [];
        this.legalCases = lsL ? JSON.parse(lsL) : [];
        this.accountability = lsA ? JSON.parse(lsA) : [];
      } catch { this.complaints = []; this.sars = []; this.phsoCases = []; this.legalCases = []; this.accountability = []; }
    },
    async _loadFromFiles() {
      const [complaintsRes, sarsRes] = await Promise.all([
        fetch("data/complaints.json"),
        fetch("data/sars.json"),
      ]);
      this.complaints = await complaintsRes.json();
      this.sars = await sarsRes.json();
    },
    save() {
      localStorage.setItem(this.key(STORAGE_KEYS.complaints), JSON.stringify(this.complaints));
      localStorage.setItem(this.key(STORAGE_KEYS.sars), JSON.stringify(this.sars));
      localStorage.setItem(this.key(STORAGE_KEYS.phso), JSON.stringify(this.phsoCases));
      localStorage.setItem(this.key(STORAGE_KEYS.legal), JSON.stringify(this.legalCases));
      localStorage.setItem(this.key(STORAGE_KEYS.accountability), JSON.stringify(this.accountability));
      localStorage.setItem(STORAGE_KEYS.users, JSON.stringify(this.users));
      localStorage.setItem(STORAGE_KEYS.session, JSON.stringify(this.session));
    },
    async syncFromServer() {
      try {
        const res = await serverFetch('/complaints/');
        if (!res.ok) throw new Error('Failed to load complaints from server');
        const list = await res.json();
        this.complaints = list.map(sc => ({
          id: sc.id,
          title: sc.title,
          dateFiled: sc.date_filed,
          institution: sc.institution,
          contactPerson: sc.contact_person,
          complaintContent: sc.complaint_content,
          linkedSAR: sc.linked_sar,
          concerns: (sc.concerns || []).map(cc => ({
            id: cc.id,
            summary: cc.summary,
            details: cc.details,
            evidence: cc.evidence || [],
            response: cc.response,
            decisionMaker: cc.decision_maker,
            responseDate: cc.response_date
          })),
          status: sc.status,
          escalationPath: [sc.status].filter(Boolean),
          isPasswordProtected: sc.is_password_protected,
          passwordHint: sc.password_hint || '',
          attachments: [],
          history: (sc.histories || []).map(h => ({ date: h.date, event: h.event, hash: h.hash }))
        }));
        this.save();
      } catch (e) {
        console.warn(String(e));
      }
    },
    upsertComplaint(newComplaint) {
      const idx = this.complaints.findIndex(c => c.id === newComplaint.id);
      if (idx >= 0) this.complaints[idx] = newComplaint; else this.complaints.push(newComplaint);
      this.save();
    },
    getComplaint(id) { return this.complaints.find(c => c.id === id); },
    nextComplaintId() {
      const num = this.complaints.reduce((max, c) => Math.max(max, parseInt((c.id||"").split("_")[1]||"0", 10)), 0) + 1;
      return `cmp_${String(num).padStart(3, "0")}`;
    },
    nextConcernId(complaint) {
      const num = (complaint.concerns||[]).reduce((max, c) => Math.max(max, parseInt((c.id||"").split("_")[1]||"0", 10)), 0) + 1;
      return `conc_${String(num).padStart(3, "0")}`;
    },
    nextPhsoId() {
      const num = this.phsoCases.reduce((max, p) => Math.max(max, parseInt((p.id||"").split("_")[1]||"0", 10)), 0) + 1;
      return `phso_${String(num).padStart(3, "0")}`;
    },
    nextLegalId() {
      const num = this.legalCases.reduce((max, p) => Math.max(max, parseInt((p.id||"").split("_")[1]||"0", 10)), 0) + 1;
      return `legal_${String(num).padStart(3, "0")}`;
    },
    async _openIdb() {
      return new Promise((resolve, reject) => {
        const req = indexedDB.open("complaints-tracker-idb", 1);
        req.onupgradeneeded = () => {
          const db = req.result;
          if (!db.objectStoreNames.contains("files")) {
            db.createObjectStore("files", { keyPath: "key" }); // key = `${complaintId}/${filename}`
          }
        };
        req.onsuccess = () => { this.idb = req.result; resolve(this.idb); };
        req.onerror = () => reject(req.error);
      });
    },
    async saveFilesForComplaint(complaintId, fileList) {
      if (!fileList || !fileList.length) return [];
      const db = this.idb || (await this._openIdb());
      const tx = db.transaction("files", "readwrite");
      const store = tx.objectStore("files");
      const saved = [];
      for (const file of fileList) {
        const arrayBuffer = await file.arrayBuffer();
        const key = `${complaintId}/${file.name}`;
        await new Promise((res, rej) => {
          const putReq = store.put({ key, name: file.name, type: file.type, size: file.size, data: arrayBuffer });
          putReq.onsuccess = () => res();
          putReq.onerror = () => rej(putReq.error);
        });
        saved.push({ key, name: file.name, type: file.type, size: file.size });
      }
      await tx.done?.catch?.(() => {});
      return saved;
    },
    async saveFilesForConcern(complaintId, concernId, fileList) {
      if (!fileList || !fileList.length) return [];
      const db = this.idb || (await this._openIdb());
      const tx = db.transaction("files", "readwrite");
      const store = tx.objectStore("files");
      const saved = [];
      for (const file of fileList) {
        const arrayBuffer = await file.arrayBuffer();
        const key = `${complaintId}/concerns/${concernId}/${file.name}`;
        await new Promise((res, rej) => {
          const putReq = store.put({ key, name: file.name, type: file.type, size: file.size, data: arrayBuffer });
          putReq.onsuccess = () => res();
          putReq.onerror = () => rej(putReq.error);
        });
        saved.push({ key, name: file.name, type: file.type, size: file.size });
      }
      await tx.done?.catch?.(() => {});
      return saved;
    },
    async saveFilesForConcernResponse(complaintId, concernId, responseId, fileList) {
      if (!fileList || !fileList.length) return [];
      const db = this.idb || (await this._openIdb());
      const tx = db.transaction("files", "readwrite");
      const store = tx.objectStore("files");
      const saved = [];
      for (const file of fileList) {
        const arrayBuffer = await file.arrayBuffer();
        const key = `${complaintId}/concerns/${concernId}/responses/${responseId}/${file.name}`;
        await new Promise((res, rej) => {
          const putReq = store.put({ key, name: file.name, type: file.type, size: file.size, data: arrayBuffer });
          putReq.onsuccess = () => res();
          putReq.onerror = () => rej(putReq.error);
        });
        saved.push({ key, name: file.name, type: file.type, size: file.size });
      }
      await tx.done?.catch?.(() => {});
      return saved;
    },
    async listFiles(complaintId) {
      const db = this.idb || (await this._openIdb());
      const tx = db.transaction("files", "readonly");
      const store = tx.objectStore("files");
      const result = [];
      return new Promise((resolve, reject) => {
        const req = store.openCursor();
        req.onsuccess = () => {
          const cursor = req.result;
          if (cursor) {
            if (cursor.key.startsWith(`${complaintId}/`)) result.push(cursor.value);
            cursor.continue();
          } else resolve(result);
        };
        req.onerror = () => reject(req.error);
      });
    },
    async listConcernFiles(complaintId, concernId) {
      const all = await this.listFiles(complaintId);
      return all.filter(f => f.key.startsWith(`${complaintId}/concerns/${concernId}/`));
    },
    async getFile(key) {
      const db = this.idb || (await this._openIdb());
      const tx = db.transaction("files", "readonly");
      const store = tx.objectStore("files");
      return new Promise((resolve, reject) => {
        const req = store.get(key);
        req.onsuccess = () => resolve(req.result);
        req.onerror = () => reject(req.error);
      });
    }
  };

  // UI state
  let accSort = { key: 'subject', dir: 'asc' };

  // UI
  function setupTabs() {
    const buttons = qsa(".tab");
    buttons.forEach(btn => btn.addEventListener("click", () => {
      buttons.forEach(b => b.classList.remove("active"));
      qsa(".panel").forEach(p => p.classList.remove("active"));
      btn.classList.add("active");
      const tab = btn.dataset.tab;
      const panel = qs(`#panel-${tab}`);
      if (panel) panel.classList.add("active");
      // Trigger per-tab renders when the tab becomes active
      if (tab === 'calendar') renderCalendar();
      if (tab === 'legal') renderLegalOverview();
      if (tab === 'accountability') renderAccountability();
      if (tab === 'institutions') renderInstitutions();
      if (tab === 'all') renderComplaintsList();
      if (tab === 'dashboard') { computeMetrics(); renderSearch(); renderFilters(); }
      if (tab === 'details') renderDetailsPlaceholder();
      if (tab === 'resources') renderResources();
    }));
  }

  function setupThemeToggle() {
    const prefersDark = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
    const saved = localStorage.getItem(STORAGE_KEYS.theme);
    const initial = saved ? saved : (prefersDark ? 'dark' : 'light');
    document.documentElement.dataset.theme = initial;
    const toggle = qs('#themeToggle');
    toggle.checked = initial === 'dark';
    toggle.addEventListener('change', () => {
      const theme = toggle.checked ? 'dark' : 'light';
      document.documentElement.dataset.theme = theme;
      localStorage.setItem(STORAGE_KEYS.theme, theme);
    });
    // Redact toggle
    const redactToggle = qs('#redactToggle');
    const redactSaved = localStorage.getItem('complaintsTracker.redact') === '1';
    if (redactToggle) {
      redactToggle.checked = redactSaved;
      redactToggle.addEventListener('change', () => {
        localStorage.setItem('complaintsTracker.redact', redactToggle.checked ? '1' : '0');
        renderAll();
      });
    }
    // Customize button
    const customizeBtn = qs('#customizeBtn');
    if (customizeBtn) customizeBtn.addEventListener('click', openCustomizeModal);
  }

  function openCustomizeModal() {
    const root = qs('#modalRoot'); if (!root) return;
    const prefs = JSON.parse(localStorage.getItem('complaintsTracker.customTheme')||'{}');
    const font = prefs.font || 'system-ui, -apple-system, Segoe UI, Roboto';
    const text = prefs.text || '';
    const bg = prefs.bg || '';
    const accent = prefs.accent || '';
    const fontSize = prefs.fontSize || 14;
    const highContrast = !!prefs.highContrast;
    const largeSpacing = !!prefs.largeSpacing;
    root.innerHTML = `
      <div class="modal-backdrop" id="customModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">Custom Settings</div>
            <button class="btn secondary" id="customClose">Close</button>
          </div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row">
                <label>Font
                  <select id="customFontSel">
                    <option value="system-ui, -apple-system, Segoe UI, Roboto">System UI</option>
                    <option value="Inter, system-ui, -apple-system, Segoe UI, Roboto">Inter</option>
                    <option value="Roboto, system-ui, -apple-system, Segoe UI">Roboto</option>
                    <option value="'Segoe UI', Tahoma, Geneva, Verdana, sans-serif">Segoe UI</option>
                    <option value="'Helvetica Neue', Arial, sans-serif">Helvetica Neue</option>
                    <option value="Georgia, 'Times New Roman', serif">Georgia</option>
                    <option value="'Merriweather', Georgia, serif">Merriweather</option>
                    <option value="'SF Pro Display', -apple-system, system-ui">SF Pro</option>
                    <option value="'PT Serif', Georgia, serif">PT Serif</option>
                    <option value="'Source Sans Pro', system-ui, -apple-system, Segoe UI">Source Sans Pro</option>
                  </select>
                </label>
                <label>Text Color<input id="customText" type="color" value="${text||'#000000'}" /></label>
              </div>
              <div class="form-row">
                <label>Background Color<input id="customBg" type="color" value="${bg||'#ffffff'}" /></label>
                <label>Accent Color<input id="customAccent" type="color" value="${accent||'#0a66d1'}" /></label>
              </div>
              <div class="form-row">
                <label>Dark Theme Background<input id="customDarkBg" type="color" value="${(prefs.darkBg||'')||'#0b0c10'}" /></label>
                <label>Light Theme Background<input id="customLightBg" type="color" value="${(prefs.lightBg||'')||'#eef1f5'}" /></label>
              </div>
              <div class="form-row">
                <label>Font Size <input id="customFontSize" type="range" min="12" max="20" step="1" value="${fontSize}" /></label>
                <label>Preset
                  <select id="customPreset">
                    <option value="">None</option>
                    <option value="midnight">Midnight</option>
                    <option value="ocean">Ocean</option>
                    <option value="forest">Forest</option>
                    <option value="highcontrast">High Contrast</option>
                  </select>
                </label>
              </div>
              <div class="form-row">
                <label class="chip"><input type="checkbox" id="customHC" ${highContrast?'checked':''}/> High Contrast</label>
                <label class="chip"><input type="checkbox" id="customLS" ${largeSpacing?'checked':''}/> Larger Spacing</label>
              </div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="customApply">Apply</button>
            <button class="btn secondary" id="customReset">Reset</button>
          </div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#customClose').addEventListener('click', close);
    qs('#customModal').addEventListener('click', (e) => { if (e.target.id === 'customModal') close(); });
    const presetSel = qs('#customPreset');
    presetSel?.addEventListener('change', () => {
      const v = presetSel.value;
      const set = (id,val) => { const el=qs(id); if (el) el.value = val; };
      if (v === 'midnight') { set('#customText','#e6e6e6'); set('#customBg','#0b0c10'); set('#customAccent','#3aa0ff'); }
      if (v === 'ocean') { set('#customText','#0b2239'); set('#customBg','#e8f4ff'); set('#customAccent','#0a66d1'); }
      if (v === 'forest') { set('#customText','#0f2e1d'); set('#customBg','#ecf8f1'); set('#customAccent','#0f8c55'); }
      if (v === 'highcontrast') { set('#customText','#000000'); set('#customBg','#ffffff'); set('#customAccent','#000000'); const hc=qs('#customHC'); if (hc) hc.checked=true; }
    });
    qs('#customApply').addEventListener('click', () => {
      const newPrefs = {
        font: (qs('#customFontSel').value||''),
        text: qs('#customText').value||'',
        bg: qs('#customBg').value||'',
        accent: qs('#customAccent').value||'',
        darkBg: qs('#customDarkBg').value||'',
        lightBg: qs('#customLightBg').value||'',
        fontSize: parseInt(qs('#customFontSize').value||'14',10),
        highContrast: !!qs('#customHC').checked,
        largeSpacing: !!qs('#customLS').checked
      };
      localStorage.setItem('complaintsTracker.customTheme', JSON.stringify(newPrefs));
      applyCustomTheme();
      close();
    });
    qs('#customReset').addEventListener('click', () => {
      localStorage.removeItem('complaintsTracker.customTheme');
      applyCustomTheme();
      close();
    });
  }

  function applyCustomTheme() {
    const prefs = JSON.parse(localStorage.getItem('complaintsTracker.customTheme')||'{}');
    const root = document.documentElement;
    if (prefs.text) root.style.setProperty('--text', prefs.text);
    if (prefs.bg) root.style.setProperty('--bg', prefs.bg);
    if (prefs.darkBg && document.documentElement.dataset.theme === 'dark') root.style.setProperty('--bg', prefs.darkBg);
    if (prefs.lightBg && document.documentElement.dataset.theme === 'light') root.style.setProperty('--bg', prefs.lightBg);
    if (prefs.accent) root.style.setProperty('--accent', prefs.accent);
    if (prefs.font) document.body.style.fontFamily = prefs.font;
    if (prefs.fontSize) document.body.style.fontSize = prefs.fontSize + 'px';
    if (prefs.highContrast) {
      root.style.setProperty('--text', '#000');
      root.style.setProperty('--bg', '#fff');
      root.style.setProperty('--accent', '#000');
      root.style.setProperty('--danger', '#000');
      document.body.style.setProperty('filter','contrast(1.05)');
    } else {
      document.body.style.removeProperty('filter');
    }
    if (prefs.largeSpacing) {
      document.body.style.lineHeight = '1.7';
      document.body.style.letterSpacing = '0.2px';
    } else {
      document.body.style.removeProperty('line-height');
      document.body.style.removeProperty('letter-spacing');
    }
    if (!prefs.text && !prefs.bg && !prefs.accent) {
      // clear overrides
      root.style.removeProperty('--text');
      root.style.removeProperty('--bg');
      root.style.removeProperty('--accent');
      document.body.style.removeProperty('font-family');
      document.body.style.removeProperty('font-size');
    }
  }

  function renderFilters() {
    const instSel = qs("#filterInstitution");
    const statusSel = qs("#filterStatus");
    const dateSel = qs('#filterDate');
    const segSel = qs('#segmentSelect');
    const institutions = Array.from(new Set(Data.complaints.map(c => c.institution).filter(Boolean))).sort();
    const statuses = Array.from(new Set(Data.complaints.map(c => c.status).filter(Boolean))).sort();
    instSel.innerHTML = `<option value="">All Institutions</option>` + institutions.map(i => `<option>${i}</option>`).join("");
    statusSel.innerHTML = `<option value="">All Statuses</option>` + statuses.map(s => `<option>${s}</option>`).join("");
    if (dateSel && !dateSel.value) {
      dateSel.value = '';
    }
    if (segSel) {
      const segments = JSON.parse(localStorage.getItem('complaintsTracker.segments')||'[]');
      segSel.innerHTML = `<option value="">Segments</option>` + segments.map(s => `<option value="${s.id}">${s.name}</option>`).join('');
    }
  }

  function computeMetrics() {
    const total = Data.complaints.length;
    const escalated = Data.complaints.filter(c => (c.status||"").toLowerCase().includes("escalated")).length;
    const unresolved = Data.complaints.filter(c => !/(resolved|closed)/i.test(c.status || "")).length;
    qs("#metricTotal").textContent = String(total);
    qs("#metricEscalated").textContent = String(escalated);
    qs("#metricUnresolved").textContent = String(unresolved);
  }

  function monthsBetween(d1Iso, d2Iso) {
    if (!d1Iso || !d2Iso) return 0;
    const d1 = new Date(d1Iso);
    const d2 = new Date(d2Iso);
    let months = (d2.getFullYear() - d1.getFullYear()) * 12 + (d2.getMonth() - d1.getMonth());
    if (d2.getDate() < d1.getDate()) months -= 1;
    return Math.max(0, months);
  }

  function computeWarnings() {
    const container = qs('#warningsContainer');
    const card = qs('#warningsCard');
    if (!container || !card) return;
    const items = [];
    const todayIso = new Date().toISOString().slice(0,10);
    for (const c of Data.complaints) {
      const freq = (c.expectedResponseFrequency||'').toLowerCase();
      const last = c.lastResponseDate || c.dateFiled; // fallback
      if (freq) {
        const daysOverdue = Math.floor((new Date(todayIso) - new Date(last)) / (1000*60*60*24));
        const m = monthsBetween(last, todayIso);
        const overdue = (freq === 'weekly' && daysOverdue >= 7) || (freq === 'monthly' && m >= 1) || (freq === 'quarterly' && m >= 3);
        if (overdue) {
          const label = freq === 'weekly' ? `${Math.floor(daysOverdue/7)} weeks overdue` : `${m} months overdue`;
          items.push({ id: c.id, text: `❗️ ${label} – ${freq.charAt(0).toUpperCase()+freq.slice(1)} contact required.`, c });
          c.breachFlag = true;
        }
      }
      if (c.breachFlag && !items.find(it => it.id === c.id)) {
        items.push({ id: c.id, text: `🚫 Agreement possibly violated – review terms.`, c });
      }
    }
    if (!items.length) { card.style.display = 'none'; container.innerHTML = ''; return; }
    card.style.display = '';
    container.innerHTML = items.map(it => `
      <div class="list-item warn">
        <div>
          <div><strong>${it.c.title}</strong></div>
          <div class="list-meta">${it.text}</div>
        </div>
        <div><button class="btn secondary" data-id="${it.id}">Open</button></div>
      </div>
    `).join('');
    container.onclick = (e) => {
      const btn = e.target.closest('button[data-id]');
      if (!btn) return;
      const c = Data.getComplaint(btn.getAttribute('data-id'));
      if (c) showComplaintDetails(c);
    };
  }

  function renderComplaintsList(list) {
    const container = qs("#complaintsList");
    container.innerHTML = "";
    (list || Data.complaints).forEach(c => {
      const div = document.createElement("div");
      div.className = "list-item";
      div.innerHTML = `
        <div>
          <div><strong>${c.title}</strong></div>
          <div class="list-meta">${c.institution || ""} • ${fmtDate(c.dateFiled)} • ${c.status || ""}</div>
          <div class="list-meta">ID: <span class="mono">${c.id}</span></div>
          <div class="stack">
            ${(c.escalationPath||[]).map(e => `<span class="chip">${e}</span>`).join(" ")}
            ${c.isPasswordProtected ? '<span class="chip protected">Protected</span>' : ''}
            ${c.linkedSAR ? '<span class="chip">Linked SAR: ' + c.linkedSAR + '</span>' : ''}
            ${renderStatusChip(c)}
          </div>
        </div>
        <div class="list-actions">
          <button class="btn secondary" data-action="view" data-id="${c.id}">View</button>
          <button class="btn secondary" data-action="sar" data-id="${c.id}" ${c.linkedSAR?"":"disabled"}>SAR</button>
        </div>`;
      container.appendChild(div);
    });

    container.addEventListener("click", (e) => {
      const t = e.target;
      if (!(t instanceof HTMLElement)) return;
      const action = t.getAttribute("data-action");
      const id = t.getAttribute("data-id");
      if (!action || !id) return;
      const c = Data.getComplaint(id);
      if (!c) return;
      if (action === "view") showComplaintDetails(c);
      if (action === "sar" && c.linkedSAR) showLinkedSar(c.linkedSAR);
    }, { once: true });
  }

  function renderSearch() {
    const input = qs("#searchInput");
    const instSel = qs("#filterInstitution");
    const statusSel = qs("#filterStatus");
    const dateSel = qs('#filterDate');
    const segSel = qs('#segmentSelect');
    const results = qs("#searchResults");
    const apply = () => {
      const q = (input.value || "").toLowerCase();
      const inst = instSel.value;
      const stat = statusSel.value;
      const date = dateSel && dateSel.value;
      const filtered = Data.complaints.filter(c => {
        const matchesQ = !q || JSON.stringify(c).toLowerCase().includes(q);
        const matchesI = !inst || c.institution === inst;
        const matchesS = !stat || c.status === stat;
        const matchesD = !date || (c.dateFiled||'').slice(0,10) === date;
        return matchesQ && matchesI && matchesS && matchesD;
      });
      results.innerHTML = "";
      if (!Data.complaints.length) {
        results.innerHTML = '<div class="card"><div class="section-title">How to Use</div><div>No cases yet. Click <strong>Add Complaint</strong> to start tracking your case.</div></div>';
        return;
      }
      filtered.forEach(c => {
        const div = document.createElement("div");
        div.className = "list-item";
        div.innerHTML = `<div><strong>${c.title}</strong><div class="list-meta">${c.institution} • ${c.status} • ${fmtDate(c.dateFiled)}</div></div><div>${renderStatusChip(c)} <button class="btn secondary" data-id="${c.id}">Open</button></div>`;
        results.appendChild(div);
      });
    };
    [input, instSel, statusSel, dateSel, segSel].filter(Boolean).forEach(el => el.addEventListener("input", apply));
    if (segSel) segSel.addEventListener('change', () => {
      const id = segSel.value; if (!id) return;
      const segments = JSON.parse(localStorage.getItem('complaintsTracker.segments')||'[]');
      const seg = segments.find(s => s.id === id); if (!seg) return;
      input.value = seg.q || '';
      instSel.value = seg.inst || '';
      statusSel.value = seg.stat || '';
      if (dateSel) dateSel.value = seg.date || '';
      apply();
    });
    const saveBtn = qs('#segmentSaveBtn');
    const delBtn = qs('#segmentDeleteBtn');
    saveBtn?.addEventListener('click', () => {
      const segments = JSON.parse(localStorage.getItem('complaintsTracker.segments')||'[]');
      const name = prompt('Segment name:'); if (!name) return;
      const id = 'seg_'+Math.random().toString(36).slice(2,7);
      segments.push({ id, name, q: input.value||'', inst: instSel.value||'', stat: statusSel.value||'', date: dateSel?.value||'' });
      localStorage.setItem('complaintsTracker.segments', JSON.stringify(segments));
      renderFilters();
      segSel.value = id; // select new
    });
    delBtn?.addEventListener('click', () => {
      const id = segSel?.value; if (!id) return;
      const segments = JSON.parse(localStorage.getItem('complaintsTracker.segments')||'[]');
      const next = segments.filter(s => s.id !== id);
      localStorage.setItem('complaintsTracker.segments', JSON.stringify(next));
      renderFilters();
      if (segSel) segSel.value = '';
    });
    qs("#clearFiltersBtn").addEventListener("click", () => { if (input) input.value = ""; if (instSel) instSel.value = ""; if (statusSel) statusSel.value = ""; if (dateSel) dateSel.value = ""; apply(); });
    apply();
    results.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-id]");
      if (!btn) return;
      const c = Data.getComplaint(btn.getAttribute("data-id"));
      if (c) showComplaintDetails(c);
    });
  }

  function renderStatusChip(complaint) {
    const status = (complaint.status||'').toLowerCase();
    if (/refus|refused|rejected|declined/.test(status)) return '<span class="chip status-refused">⛔ Refused</span>';
    if (/resolved|closed/.test(status)) return '<span class="chip status-green">🟢 Resolved</span>';
    if (/escalated|phso|appeal|iopc|chief|legal/.test(status)) return '<span class="chip status-amber">🟠 Escalated</span>';
    return '<span class="chip status-red">🔴 Unresolved</span>';
  }

  function maskText(text) {
    if (!text) return '';
    // Basic PII redaction patterns (expandable): emails, phone numbers, badge/employee numbers like ABC1234 or #12345
    const email = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/ig;
    const phone = /\b(?:\+?\d[\d\s\-()]{7,}\d)\b/g;
    const badge = /\b(?:badge|warrant|employee|staff)\s*#?\s*\d{3,}\b/ig;
    const idlike = /\b[A-Z]{2,5}\d{3,6}\b/g; // simple token pattern
    return String(text)
      .replace(email, '[redacted-email]')
      .replace(phone, '[redacted-phone]')
      .replace(badge, '[redacted-id]')
      .replace(idlike, '[redacted-id]');
  }

  function redactComplaintDeep(complaint) {
    const redacted = JSON.parse(JSON.stringify(complaint));
    const overrides = complaint.redactOverrides || {};
    const redactFields = (obj, keys) => { keys.forEach(k => { if (obj[k]) obj[k] = maskText(obj[k]); }); };
    const rootKeys = ['title','institution','contactPerson','complaintContent','institutionAddress','institutionEmail','status','passwordHint','agreedTerms'];
    redactFields(redacted, rootKeys.filter(k => overrides[k] !== false));
    (redacted.concerns||[]).forEach(c => {
      const ck = c.id || '';
      const cov = (overrides.concerns||{})[ck] || {};
      redactFields(c, ['summary','details','decisionMaker','response'].filter(k => cov[k] !== false));
      c.evidence = (c.evidence||[]).map(e => maskText(e));
      c.notes = (c.notes||[]).map(n => ({ ...n, text: cov.notesText===false?n.text:maskText(n.text), urls: (n.urls||[]).map(u => cov.notesUrls===false?u:maskText(u)) }));
      c.responses = (c.responses||[]).map(r => ({ ...r, decisionMaker: cov.responsesDecision===false?r.decisionMaker:maskText(r.decisionMaker), text: cov.responsesText===false?r.text:maskText(r.text), urls: (r.urls||[]).map(u => cov.responsesUrls===false?u:maskText(u)) }));
      // attachments filtering by safety flag from overrides
      if (Array.isArray(c.attachments)) {
        c.attachments = c.attachments.filter(key => {
          const ok = ((overrides.safeAttachments||[]).includes(key));
          return ok; // only include marked safe in redacted view
        });
      }
    });
    return redacted;
  }

  function populateLinkedSarSelect() {
    const sel = qs("#linkedSarSelect");
    sel.innerHTML = `<option value="">None</option>` + Data.sars.map(s => `<option value="${s.id}">${s.id} — ${s.title}</option>`).join("");
  }

  async function populateInstitutionSelect() {
    const sel = qs('#institutionSelect');
    const addr = qs('#institutionAddress');
    const mail = qs('#institutionEmail');
    const csvRows = await loadInstitutions();
    const added = JSON.parse(localStorage.getItem('complaintsTracker.addedInstitutions')||'[]');
    const rows = [...csvRows, ...added];
    const dl = qs('#institutionList');
    if (dl) dl.innerHTML = rows.map(r => `<option value="${r.name}" data-address="${r.address||''}" data-email="${r.email||''}"></option>`).join('');
    sel.addEventListener('input', () => {
      const val = sel.value;
      const match = rows.find(r => r.name === val);
      if (match) {
        addr.value = match.address || '';
        mail.value = match.email || '';
        const contact = qs('#contactPerson');
        if (contact && match.defaultContact) contact.value = match.defaultContact;
        const freqSel = qs('select[name="expectedResponseFrequency"]');
        if (freqSel && match.defaultExpectedResponseFrequency) freqSel.value = match.defaultExpectedResponseFrequency;
      }
    });
    const addBtn = qs('#addInstitutionBtn');
    if (addBtn) addBtn.onclick = () => openAddInstitutionModal(sel);
  }

  function exportInstitutionsCsv(rows) {
    const headers = ['name','address','email','cases'];
    const csv = [headers.join(','), ...rows.map(r => {
      const line = [r.name||'', r.address||'', r.email||'', String(r.caseCount||0)];
      return line.map(s => /[",\n]/.test(s) ? '"'+s.replace(/"/g,'""')+'"' : s).join(',');
    })].join('\n');
    downloadBlob(csv, `institutions-${Date.now()}.csv`, 'text/csv');
  }

  async function renderInstitutions() {
    const panel = qs('#panel-institutions');
    if (!panel || !panel.classList.contains('active')) return;
    const container = qs('#institutionsContainer');
    const searchInput = qs('#instSearchInput');
    const csvRows = await loadInstitutions();
    const added = JSON.parse(localStorage.getItem('complaintsTracker.addedInstitutions')||'[]');
    const merged = [...csvRows, ...added].reduce((acc, r) => {
      const name = (r.name||'').trim(); if (!name) return acc;
      if (!acc[name]) acc[name] = { name, address: r.address||'', email: r.email||'', caseCount: 0 };
      return acc;
    }, {});
    // compute case counts
    for (const c of Data.complaints) {
      const key = (c.institution||'').trim(); if (!key) continue;
      if (!merged[key]) merged[key] = { name: key, address: '', email: '', caseCount: 0 };
      merged[key].caseCount += 1;
    }
    let rows = Object.values(merged).sort((a,b)=>a.name.localeCompare(b.name));
    const apply = () => {
      const q = (searchInput?.value||'').toLowerCase();
      const view = rows.filter(r => !q || JSON.stringify(r).toLowerCase().includes(q));
      container.innerHTML = `
        <div class="card">
          <table class="table">
            <thead><tr><th>Name</th><th>Address</th><th>Email</th><th>Cases</th><th></th></tr></thead>
            <tbody>
              ${view.map(r => `
                <tr>
                  <td>${r.name}</td>
                  <td>${r.address||''}</td>
                  <td>${r.email||''}</td>
                  <td>${r.caseCount||0}</td>
                  <td>
                    <button class="btn secondary" data-open="${r.name}">Open Cases</button>
                    <button class="btn secondary" data-edit="${r.name}">Edit</button>
                    <button class="btn secondary" data-del="${r.name}">Delete</button>
                  </td>
                </tr>
              `).join('') || '<tr><td colspan="5">No institutions</td></tr>'}
            </tbody>
          </table>
        </div>`;
    };
    if (searchInput) searchInput.oninput = apply;
    apply();
    qs('#instAddBtn')?.addEventListener('click', () => openInstitutionEditModal({ name: '', address: '', email: '', defaultContact: '', defaultExpectedResponseFrequency: '' }));
    qs('#instExportBtn')?.addEventListener('click', () => exportInstitutionsCsv(rows));
    qs('#instImportBtn')?.addEventListener('click', () => qs('#instImportInput')?.click());
    qs('#instImportInput')?.addEventListener('change', async (e) => {
      const file = e.target.files && e.target.files[0]; if (!file) return;
      try {
        const text = await file.text();
        const lines = text.split(/\r?\n/).filter(Boolean);
        if (!lines.length) return;
        const hasHeader = /name/i.test(lines[0]);
        const body = hasHeader ? lines.slice(1) : lines;
        const incoming = body.map(l => {
          const parts = l.split(/,(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)/);
          return { name: (parts[0]||'').replace(/^\"|\"$/g,''), address: (parts[1]||'').replace(/^\"|\"$/g,''), email: (parts[2]||'').replace(/^\"|\"$/g,'') };
        }).filter(r => r.name);
        const store = JSON.parse(localStorage.getItem('complaintsTracker.addedInstitutions')||'[]');
        const byName = new Map(store.map(r => [r.name, r]));
        for (const r of incoming) {
          if (byName.has(r.name)) {
            // merge non-empty fields without overwriting
            const cur = byName.get(r.name);
            byName.set(r.name, { ...cur, address: cur.address || r.address, email: cur.email || r.email });
          } else {
            byName.set(r.name, r);
          }
        }
        localStorage.setItem('complaintsTracker.addedInstitutions', JSON.stringify(Array.from(byName.values())));
        renderInstitutions();
        alert('Institutions imported.');
      } finally { e.target.value = ''; }
    }, { once: true });
    container.onclick = (e) => {
      const open = e.target.closest('button[data-open]');
      const edit = e.target.closest('button[data-edit]');
      const del = e.target.closest('button[data-del]');
      if (open) {
        const name = open.getAttribute('data-open');
        openInstitutionProfile(name);
      }
      if (edit) {
        const name = edit.getAttribute('data-edit');
        const rec = rows.find(r => r.name === name) || { name, address: '', email: '' };
        openInstitutionEditModal(rec);
      }
      if (del) {
        const name = del.getAttribute('data-del');
        const conf = confirm(`Remove local override for ${name}? (Bundled CSV remains unchanged)`);
        if (!conf) return;
        const store = JSON.parse(localStorage.getItem('complaintsTracker.addedInstitutions')||'[]');
        const next = store.filter(r => r.name !== name);
        localStorage.setItem('complaintsTracker.addedInstitutions', JSON.stringify(next));
        renderInstitutions();
      }
    };
  }

  function openInstitutionProfile(name) {
    const root = qs('#modalRoot'); if (!root) return;
    const store = JSON.parse(localStorage.getItem('complaintsTracker.addedInstitutions')||'[]');
    const csvMatch = (function(){ return []; })();
    const rec = store.find(r => r.name === name) || { name };
    const cases = Data.complaints.filter(c => c.institution === name);
    const urls = Array.isArray(rec.urls) ? rec.urls : [];
    root.innerHTML = `
      <div class="modal-backdrop" id="instProfileModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">${name}</div>
            <button class="btn secondary" id="instProfileClose">Close</button>
          </div>
          <div class="modal-body">
            <div class="stack">
              <div class="list-item"><div><strong>Default Contact</strong></div><div>${rec.defaultContact||'—'}</div></div>
              <div class="list-item"><div><strong>Default Frequency</strong></div><div>${rec.defaultExpectedResponseFrequency||'—'}</div></div>
              <div class="list-item"><div><strong>Notes</strong></div><div>${rec.notes||''}</div></div>
              <div class="list-item"><div><strong>Resources</strong></div><div>${urls.map(u => u.startsWith('http')?`<a href="${u}" target="_blank" rel="noopener">${u}</a>`:u).join(', ')||'—'}</div></div>
              <div class="section-title">Cases (${cases.length})</div>
              <div class="list">${cases.map(c => `<div class=\"list-item\"><div><strong>${c.title}</strong><div class=\"list-meta\">${c.status} • ${new Date(c.dateFiled).toLocaleDateString()}</div></div><div><button class=\"btn secondary\" data-open=\"${c.id}\">Open</button></div></div>`).join('')||'<div class=\"list-item\"><div>No cases</div></div>'}</div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="bulkChaseBtn">Send 30-day chaser to open cases</button>
            <button class="btn secondary" id="editInstitutionBtn">Edit Institution</button>
          </div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#instProfileClose').addEventListener('click', close);
    qs('#editInstitutionBtn').addEventListener('click', () => { close(); openInstitutionEditModal(rec); });
    qs('#bulkChaseBtn').addEventListener('click', () => {
      const targets = cases.filter(c => !/(resolved|closed)/i.test(c.status||''));
      if (!targets.length) { alert('No open cases to chase.'); return; }
      const subject = encodeURIComponent('Request for update');
      const body = encodeURIComponent('Dear Sir/Madam,\n\nPlease provide an update on the below cases within 14 days.\n\n' + targets.map(c => `- ${c.id}: ${c.title} (${new Date(c.dateFiled).toLocaleDateString()})`).join('\n') + '\n\nKind regards');
      const mailto = `mailto:${(rec.email||'')}${'?subject='+subject+'&body='+body}`;
      window.location.href = mailto;
    });
    qs('#instProfileModal').addEventListener('click', (e) => { if (e.target.id === 'instProfileModal') close(); });
    const list = qs('#instProfileModal .list');
    if (list) list.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-open]');
      if (!btn) return;
      const c = Data.getComplaint(btn.getAttribute('data-open'));
      if (c) { close(); showComplaintDetails(c); }
    });
  }

  function openInstitutionEditModal(record) {
    const root = qs('#modalRoot'); if (!root) return;
    root.innerHTML = `
      <div class="modal-backdrop" id="instEditModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">Edit Institution</div>
            <button class="btn secondary" id="instEditClose">Close</button>
          </div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row">
                <label>Name<input id="editInstName" value="${(record.name||'').replace(/\"/g,'&quot;')}" /></label>
                <label>Address<input id="editInstAddr" value="${(record.address||'').replace(/\"/g,'&quot;')}" /></label>
              </div>
              <div class="form-row">
                <label>Email<input id="editInstEmail" type="email" value="${(record.email||'').replace(/\"/g,'&quot;')}" /></label>
                <label>Default Contact<input id="editInstContact" value="${(record.defaultContact||'').replace(/\"/g,'&quot;')}" /></label>
              </div>
              <div class="form-row">
                <label>Default Expected Response
                  <select id="editInstFreq">
                    <option value="">None</option>
                    <option ${record.defaultExpectedResponseFrequency==='Weekly'?'selected':''}>Weekly</option>
                    <option ${record.defaultExpectedResponseFrequency==='Monthly'?'selected':''}>Monthly</option>
                    <option ${record.defaultExpectedResponseFrequency==='Quarterly'?'selected':''}>Quarterly</option>
                  </select>
                </label>
                <label>Resource URLs (comma-separated)<input id="editInstUrls" value="${Array.isArray(record.urls)?record.urls.join(', '):''}" /></label>
              </div>
              <div class="form-row">
                <label>Notes<textarea id="editInstNotes" rows="3">${(record.notes||'')}</textarea></label>
              </div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="instEditSave">Save</button>
            <button class="btn secondary" id="instEditCancel">Cancel</button>
          </div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#instEditClose').addEventListener('click', close);
    qs('#instEditCancel').addEventListener('click', close);
    qs('#instEditModal').addEventListener('click', (e) => { if (e.target.id === 'instEditModal') close(); });
    qs('#instEditSave').addEventListener('click', () => {
      const name = (qs('#editInstName').value||'').trim();
      const address = (qs('#editInstAddr').value||'').trim();
      const email = (qs('#editInstEmail').value||'').trim();
      const defaultContact = (qs('#editInstContact').value||'').trim();
      const defaultExpectedResponseFrequency = (qs('#editInstFreq').value||'').trim();
      const urls = (qs('#editInstUrls').value||'').split(',').map(s=>s.trim()).filter(Boolean);
      const notes = (qs('#editInstNotes').value||'');
      if (!name) { alert('Name required'); return; }
      const store = JSON.parse(localStorage.getItem('complaintsTracker.addedInstitutions')||'[]');
      // duplicate name check (allow if editing same name)
      if (name !== record.name && store.some(r => r.name === name)) { alert('Institution with this name already exists.'); return; }
      const idx = store.findIndex(r => r.name === record.name);
      const updated = { name, address, email, defaultContact, defaultExpectedResponseFrequency, urls, notes };
      if (idx >= 0) store[idx] = updated; else store.push(updated);
      localStorage.setItem('complaintsTracker.addedInstitutions', JSON.stringify(store));
      close(); renderInstitutions();
    });
  }

  function openAddInstitutionModalInline() {
    openInstitutionEditModal({ name: '', address: '', email: '', defaultContact: '', defaultExpectedResponseFrequency: '' });
  }

  function openAddInstitutionModal(selectEl) {
    const root = qs('#modalRoot'); if (!root) return;
    root.innerHTML = `
      <div class="modal-backdrop" id="instModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">Add Institution</div>
            <button class="btn secondary" id="instCancel">Close</button>
          </div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row">
                <label>Name<input id="instName" required /></label>
                <label>Address<input id="instAddr" /></label>
              </div>
              <div class="form-row">
                <label>Email<input id="instEmail" type="email" /></label>
              </div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="instSave">Save</button>
            <button class="btn secondary" id="instCancel2">Cancel</button>
          </div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#instCancel').addEventListener('click', close);
    qs('#instCancel2').addEventListener('click', close);
    qs('#instModal').addEventListener('click', (e) => { if (e.target.id === 'instModal') close(); });
    qs('#instSave').addEventListener('click', async () => {
      const name = (qs('#instName').value||'').trim();
      const address = (qs('#instAddr').value||'').trim();
      const email = (qs('#instEmail').value||'').trim();
      if (!name) { alert('Name required'); return; }
      // Append to localStorage registry to persist locally
      const option = document.createElement('option');
      option.value = name; option.textContent = name; option.setAttribute('data-address', address); option.setAttribute('data-email', email);
      selectEl.appendChild(option);
      selectEl.value = name;
      const addr = qs('#institutionAddress');
      const mail = qs('#institutionEmail');
      if (addr) addr.value = address;
      if (mail) mail.value = email;
      // Note: On static hosting we can't write to CSV; storing selection locally
      const added = JSON.parse(localStorage.getItem('complaintsTracker.addedInstitutions')||'[]');
      added.push({ name, address, email });
      localStorage.setItem('complaintsTracker.addedInstitutions', JSON.stringify(added));
      close();
    });
  }

  function handleAddComplaint() {
    const form = qs("#complaintForm");
    form.addEventListener("submit", async (e) => {
      e.preventDefault();
      const data = Object.fromEntries(new FormData(form).entries());
      const isProtected = !!data.isPasswordProtected;
      const localId = Data.nextComplaintId();
      const baseComplaint = {
        title: data.title,
        dateFiled: data.dateFiled,
        type: data.type || '',
        institution: data.institution,
        contactPerson: data.contactPerson || "",
        complaintContent: data.complaintContent,
        linkedSAR: data.linkedSAR || null,
        concerns: [],
        status: data.status || "Filed",
        escalationPath: ["Filed"],
        isPasswordProtected: isProtected,
        passwordHint: data.passwordHint || "",
        institutionAddress: data.institutionAddress || "",
        institutionEmail: data.institutionEmail || "",
        eventDate: data.eventDate || "",
        refusalDate: data.refusalDate || "",
        expectedResponseFrequency: data.expectedResponseFrequency || "",
        lastResponseDate: data.lastResponseDate || "",
        agreedTerms: data.agreedTerms || "",
        breachFlag: !!data.breachFlag,
        attachments: [],
        history: []
      };

      if (isProtected) {
        const pwd = prompt("Set a password for this complaint (remember it):") || "";
        if (!pwd) return alert("Password required or uncheck protection.");
        baseComplaint._protected = await encryptText(JSON.stringify({ content: baseComplaint.complaintContent }), pwd);
        baseComplaint.complaintContent = "[Protected]";
      }

      const filesInput = qs('#attachmentsInput');
      if (typeof Server !== 'undefined' && isServerMode()) {
        try {
          const payload = {
            title: baseComplaint.title,
            date_filed: baseComplaint.dateFiled,
            institution: baseComplaint.institution,
            contact_person: baseComplaint.contactPerson,
            complaint_content: baseComplaint.complaintContent,
            linked_sar: baseComplaint.linkedSAR || null,
            status: baseComplaint.status,
            is_password_protected: baseComplaint.isPasswordProtected,
            password_hint: baseComplaint.passwordHint
          };
          const res = await serverFetch('/complaints/', { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify(payload) });
          const created = await res.json();
          if (!res.ok) throw new Error(created.detail || 'Create failed');
          const serverId = created.id;
          if (filesInput.files && filesInput.files.length) {
            for (const file of filesInput.files) {
              const fd = new FormData();
              fd.append('file', file);
              await serverFetch(`/complaints/${serverId}/files`, { method: 'POST', body: fd });
            }
          }
          const event = 'Complaint created';
          const dateStr = new Date().toISOString().slice(0,10);
          const hash = await sha256Hex(`|${dateStr}|${event}`);
          await serverFetch(`/complaints/${serverId}/history`, { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ date: dateStr, event, hash }) });
          alert('Complaint saved to server.');
        } catch (err) {
          console.error(err); alert(String(err));
        } finally {
          await Data.syncFromServer();
          form.reset(); renderAll();
        }
      } else {
        const complaint = { id: localId, ...baseComplaint };
        const savedFiles = await Data.saveFilesForComplaint(complaint.id, filesInput.files);
        complaint.attachments = savedFiles.map(f => f.key);
        await appendHistory(complaint, "Complaint created");
        Data.upsertComplaint(complaint);
        renderAll();
        alert("Complaint saved.");
        form.reset();
      }
    });
  }

  async function showComplaintDetails(complaint) {
    // Switch to details tab
    qsa(".tab").forEach(btn => {
      const is = btn.dataset.tab === "details";
      btn.classList.toggle("active", is);
    });
    qsa(".panel").forEach(p => p.classList.remove("active"));
    qs("#panel-details").classList.add("active");

    const el = qs("#detailsContainer");
    const sarLabel = complaint.linkedSAR ? `Linked SAR: <a href="#" id="openLinkedSar">${complaint.linkedSAR}</a>` : "No linked SAR";
    const auditOk = await verifyHistoryChain(complaint);
    const redactOn = localStorage.getItem('complaintsTracker.redact') === '1';
    const viewComplaint = redactOn ? redactComplaintDeep(complaint) : complaint;
    el.innerHTML = `
      <div class="grid">
        <div class="card">
          <div class="section-title">Overview</div>
          <div><strong>${viewComplaint.title}</strong></div>
          <div class="list-meta">${viewComplaint.institution} • ${fmtDate(viewComplaint.dateFiled)} • ${viewComplaint.status} ${renderStatusChip(viewComplaint)}</div>
          <div class="list-meta">${sarLabel}</div>
          ${(viewComplaint.eventDate||viewComplaint.refusalDate)?`<div class=\"list-meta\">Event: ${fmtDate(viewComplaint.eventDate)} ${viewComplaint.refusalDate?` • Refused: ${fmtDate(viewComplaint.refusalDate)}`:''} ${viewComplaint.eventDate?` • ${monthsSinceText(viewComplaint.eventDate)} since event`:''}</div>`:''}
          ${(viewComplaint.expectedResponseFrequency||viewComplaint.lastResponseDate||viewComplaint.agreedTerms||viewComplaint.breachFlag) ? `
            <div class="stack" style="margin-top:8px;">
              ${viewComplaint.expectedResponseFrequency ? `<div class=\"chip\">Expected: ${viewComplaint.expectedResponseFrequency}</div>` : ''}
              ${viewComplaint.lastResponseDate ? `<div class=\"chip\">Last Response: ${fmtDate(viewComplaint.lastResponseDate)}</div>` : ''}
              ${viewComplaint.agreedTerms ? `<div class=\"chip\">Agreed Terms noted</div>` : ''}
              ${viewComplaint.breachFlag ? `<div class=\"chip status-red\">Breach</div>` : ''}
            </div>
          `: ''}
          <div style="margin-top:8px;">${viewComplaint.complaintContent}</div>
          ${viewComplaint.isPasswordProtected ? `<div class="chip protected" style="margin-top:8px;">Password Protected${viewComplaint.passwordHint?` — Hint: ${viewComplaint.passwordHint}`:""}</div>` : ""}
          <div class="chip" style="margin-top:8px;">Audit Trail: ${auditOk ? "Valid" : "Invalid"}</div>
          <div class="form-actions" style="margin-top:10px;">
            ${complaint.isPasswordProtected ? `<button class="btn" id="unlockBtn">Unlock</button>` : ""}
            <button class="btn secondary" id="genSummaryBtn">Generate Summary</button>
            <button class="btn secondary" id="chaserBtn">Chaser</button>
            <button class="btn secondary" id="closureBtn">Closure</button>
            <button class="btn secondary" id="redactControlsBtn">Redaction Controls</button>
            <button class="btn" id="shareRedactedBtn">Share Redacted</button>
            <button class="btn secondary" id="shareFullBtn">Share Full</button>
            <button class="btn secondary" id="shareConcernsBtn">Share Concerns</button>
            <button class="btn secondary" id="suggestEscBtn">Suggest Escalation</button>
            <button class="btn secondary" id="markLegalBtn">Mark as Legal</button>
            <button class="btn secondary" id="escTemplateBtn">Escalation Template</button>
            <button class="btn secondary" id="exportMdBtn">Export Markdown</button>
            <button class="btn secondary" id="exportNbBtn">Export Notebook</button>
            <button class="btn secondary" id="editBtn">Edit</button>
          </div>
          <div class="form-actions" style="margin-top:8px;">
            <button class="btn" id="escalatePhsoBtn">Escalate to PHSO</button>
            <button class="btn secondary" id="accReferralBtn">Accountability Referral</button>
          </div>
        </div>
        <div class="card">
          <div class="section-title">Concerns</div>
          <div class="stack" id="concernsList">
            ${(viewComplaint.concerns||[]).map(cc => `
              <div class="list-item">
                <div>
                  <div><strong>${cc.summary}</strong></div>
                  <div class="list-meta">Decision: ${cc.decisionMaker || "—"} • ${fmtDate(cc.responseDate) || ""}</div>
                  <div class="list-meta">Evidence URLs: ${((cc.evidence||[]).length ? (cc.evidence||[]).map(e => (((e||'').startsWith('http://')) || ((e||'').startsWith('https://'))) ? `<a href="${e}" target="_blank" rel="noopener">${e}</a>` : e).join(", ") : "—")}</div>
                  <div class="list-meta">Attachments: ${(cc.attachments||[]).length ? `${(cc.attachments||[]).length} file(s)` : "—"}</div>
                  ${(Array.isArray(cc.notes) && cc.notes.length) ? `<div class=\"list-meta\"><strong>Notes</strong></div>` : ''}
                  ${(Array.isArray(cc.notes) ? cc.notes : []).map(n => `<div class=\"list-meta\">• ${n.text || ''} ${(Array.isArray(n.urls)?n.urls:[]).map(u => u.startsWith('http')?`<a href=\"${u}\" target=\"_blank\" rel=\"noopener\">${u}</a>`:u).join(', ')}</div>`).join('')}
                  ${(Array.isArray(cc.responses) && cc.responses.length) ? `<div class=\"section-title\" style=\"margin-top:8px;\">Responses</div>` : ''}
                  ${(Array.isArray(cc.responses) ? cc.responses : []).map(r => `
                    <div class=\"list-item\" style=\"margin-top:6px;\">
                      <div>
                        <div><strong>${fmtDate(r.date)||''}</strong> — ${r.decisionMaker || 'Response'}</div>
                        <div class=\"list-meta\">${(r.urls||[]).map(u => u.startsWith('http')?`<a href=\"${u}\" target=\"_blank\" rel=\"noopener\">${u}</a>`:u).join(', ')}</div>
                      </div>
                      <div>${r.text || ''}</div>
                      <div class=\"list-meta\">Attachments: ${(r.attachments||[]).length ? `${(r.attachments||[]).length} file(s)` : '—'}</div>
                    </div>
                  `).join('')}
                </div>
                <div>
                  <div>${cc.response || ""}</div>
                  <div class="form-actions vertical-actions" style="margin-top:6px;">
                    <button class="btn secondary" data-action="addresponse" data-id="${cc.id}">Add Response</button>
                    <button class="btn secondary" data-action="edit" data-id="${cc.id}">Edit Concern</button>
                    <button class="btn secondary" data-action="delete" data-id="${cc.id}">Delete</button>
                    <button class="btn secondary" data-action="addnote" data-id="${cc.id}">Add Note</button>
                    <button class="btn secondary" data-action="addfiles" data-id="${cc.id}">Add Files</button>
                    <button class="btn secondary" data-action="shareconcern" data-id="${cc.id}">Share Concern</button>
                  </div>
                </div>
              </div>
            `).join("")}
          </div>
          <div class="form-actions" style="margin-top:10px;">
            <button class="btn" id="addConcernBtn">Add Concern</button>
          </div>
        </div>
        <div class="card">
          <div class="section-title">History</div>
          <div class="stack">
            ${(complaint.history||[]).map(h => `<div class="list-item"><div>${fmtDate(h.date)} — ${h.event}</div><div class="list-meta mono">${(h.hash||"").slice(0,16)}…</div></div>`).join("")}
          </div>
        </div>
        <div class="card">
          <div class="section-title">Attachments</div>
          <div class="stack" id="attachmentsList"></div>
        </div>
      </div>
    `;
    el.setAttribute('data-has-complaint', '1');

    // Render attachments now that the DOM is in place
    const listEl = qs('#attachmentsList');
    const files = await Data.listFiles(complaint.id);
    if (!files.length) {
      listEl.innerHTML = '<div class="list-item"><div>No attachments</div></div>';
    } else {
      for (const f of files) {
        const row = document.createElement('div');
        row.className = 'list-item';
        row.innerHTML = `<div>${f.name} <span class="list-meta">${(f.type||'')}, ${(f.size||0)} bytes</span></div><div><button class="btn secondary" data-key="${f.key}">Download</button></div>`;
        listEl.appendChild(row);
      }
      listEl.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-key]');
        if (!btn) return;
        const item = await Data.getFile(btn.getAttribute('data-key'));
        if (!item) return;
        const blob = new Blob([item.data], { type: item.type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = item.name; a.click();
        setTimeout(() => URL.revokeObjectURL(url), 500);
      });
    }

    const sarLink = qs("#openLinkedSar");
    if (sarLink && complaint.linkedSAR) sarLink.addEventListener("click", (e) => { e.preventDefault(); showLinkedSar(complaint.linkedSAR); });
    const escalateBtn = qs('#escalatePhsoBtn');
    if (escalateBtn) escalateBtn.addEventListener('click', async () => {
      complaint.status = 'Escalated to PHSO';
      complaint.escalationPath = Array.from(new Set([...(complaint.escalationPath||[]), 'Escalated to PHSO']));
      await appendHistory(complaint, 'Escalated to PHSO');
      Data.upsertComplaint(complaint);
      await autoCreatePhsoCase(complaint);
      showPhsoTab(complaint.id);
    });
    const accBtn = qs('#accReferralBtn');
    if (accBtn) accBtn.addEventListener('click', () => {
      if (!requireLogin()) return;
      const subject = complaint.contactPerson || complaint.institution || 'Unnamed Subject';
      const organisation = complaint.institution || '';
      const status = 'Open';
      const entry = { id: `subj_${Math.random().toString(36).slice(2,7)}`, subject, role: 'Contact/Institution', organisation, status, allegations: '', harm: [], evidence: [], dates: [complaint.dateFiled].filter(Boolean), linkedComplaints: [complaint.id] };
      Data.accountability.push(entry);
      Data.save();
      alert('Referred to Accountability. You can add details and charges there.');
      qsa('.tab').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === 'accountability'));
      qsa('.panel').forEach(p => p.classList.remove('active'));
      qs('#panel-accountability').classList.add('active');
      renderAccountability();
    });

    const unlockBtn = qs("#unlockBtn");
    const genSummaryBtn = qs('#genSummaryBtn');
    if (genSummaryBtn) genSummaryBtn.addEventListener('click', () => generateNegligenceSummary(complaint));
    const chaserBtn = qs('#chaserBtn');
    if (chaserBtn) chaserBtn.addEventListener('click', () => openChaserModal(complaint));
    const closureBtn = qs('#closureBtn');
    if (closureBtn) closureBtn.addEventListener('click', () => openClosureModal(complaint));
    const redBtn = qs('#redactControlsBtn');
    if (redBtn) redBtn.addEventListener('click', () => openRedactionControlsModal(complaint));
    const shareRedBtn = qs('#shareRedactedBtn');
    if (shareRedBtn) shareRedBtn.addEventListener('click', () => shareStandaloneComplaint(complaint, true));
    const shareFullBtn = qs('#shareFullBtn');
    if (shareFullBtn) shareFullBtn.addEventListener('click', () => shareStandaloneComplaint(complaint, false));
    const shareConsBtn = qs('#shareConcernsBtn');
    if (shareConsBtn) shareConsBtn.addEventListener('click', () => openShareConcernsModal(complaint));
    const suggestBtn = qs('#suggestEscBtn');
    if (suggestBtn) suggestBtn.addEventListener('click', () => {
      const path = suggestEscalationPath(complaint.type||'');
      alert(`Suggested escalation for type "${complaint.type||'Unknown'}": ${path.join(' → ')}`);
    });
    const markLegalBtn = qs('#markLegalBtn');
    if (markLegalBtn) markLegalBtn.addEventListener('click', async () => {
      complaint.status = 'Legal';
      await appendHistory(complaint, 'Marked as Legal');
      Data.upsertComplaint(complaint);
      await autoCreateLegalCase(complaint, 'Marked as Legal');
      showLegalTab(complaint.id);
    });
    const escTplBtn = qs('#escTemplateBtn');
    if (escTplBtn) escTplBtn.addEventListener('click', () => openEscalationTemplateModal(complaint));
    const exportMdBtn = qs('#exportMdBtn');
    if (exportMdBtn) exportMdBtn.addEventListener('click', () => exportComplaintMarkdown(complaint));
    const exportNbBtn = qs('#exportNbBtn');
    if (exportNbBtn) exportNbBtn.addEventListener('click', () => exportComplaintNotebook(complaint));
    if (unlockBtn) unlockBtn.addEventListener("click", async () => {
      const pwd = prompt("Enter complaint password:") || "";
      try {
        const plain = await decryptText(complaint._protected, pwd);
        const { content } = JSON.parse(plain);
        alert("Decrypted content loaded for this view only.");
        qs("#detailsContainer").querySelector(".card div:nth-child(5)").textContent = content;
      } catch {
        alert("Incorrect password or corrupted data.");
      }
    });

    qs("#addConcernBtn").addEventListener("click", () => openConcernModal(complaint));

    // Concern actions: add response/edit/delete/add note/add files
    const concernsEl = qs('#concernsList');
    concernsEl.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-action][data-id]');
      if (!btn) return;
      const action = btn.getAttribute('data-action');
      const cid = btn.getAttribute('data-id');
      const idx = (complaint.concerns||[]).findIndex(x => x.id === cid);
      if (idx < 0) return;
      const cc = complaint.concerns[idx];
      if (action === 'addresponse') { openResponseModal(complaint, cc); return; }
      if (action === 'edit') {
        openConcernModal(complaint, cc);
        return;
      }
      if (action === 'delete') {
        if (!confirm('Delete this concern?')) return;
        complaint.concerns.splice(idx, 1);
        appendHistory(complaint, `Concern deleted: ${cc.summary}`);
        Data.upsertComplaint(complaint);
        showComplaintDetails(complaint);
      }
      if (action === 'addnote') { openNoteModal(complaint, cc); return; }
      if (action === 'addfiles') {
        const finput = document.createElement('input');
        finput.type = 'file';
        finput.multiple = true;
        finput.style.display = 'none';
        document.body.appendChild(finput);
        finput.addEventListener('change', async () => {
          try {
            const saved = await Data.saveFilesForConcern(complaint.id, cc.id, finput.files);
            cc.attachments = Array.from(new Set([...(cc.attachments||[]), ...saved.map(s => s.key)]));
            appendHistory(complaint, `Concern files added: ${cc.summary}`);
            Data.upsertComplaint(complaint);
            showComplaintDetails(complaint);
          } finally {
            document.body.removeChild(finput);
          }
        }, { once: true });
        finput.click();
      }
      if (action === 'shareconcern') { openShareSingleConcernModal(complaint, cc); return; }
    });

    // Per-concern attachment downloads (delegated)
    concernsEl.addEventListener('click', async (e) => {
      const btn = e.target.closest('button[data-filekey]');
      if (!btn) return;
      const item = await Data.getFile(btn.getAttribute('data-filekey'));
      if (!item) return;
      const blob = new Blob([item.data], { type: item.type || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = item.name; a.click();
      setTimeout(() => URL.revokeObjectURL(url), 500);
    });

    qs("#editBtn").addEventListener("click", () => {
      const newStatus = prompt("Update status:", complaint.status || "") || complaint.status;
      if (newStatus && newStatus !== complaint.status) {
        complaint.status = newStatus;
        complaint.escalationPath = Array.from(new Set([...(complaint.escalationPath||[]), newStatus]));
        appendHistory(complaint, `Status updated: ${newStatus}`);
        Data.upsertComplaint(complaint);
        if (/phso/i.test(newStatus)) {
          autoCreatePhsoCase(complaint).then(() => {
            showPhsoTab(complaint.id);
          });
        }
        if (/legal|litigat|court|claim|judicial/i.test(newStatus)) {
          autoCreateLegalCase(complaint).then(() => {
            showLegalTab(complaint.id);
          });
        }
        showComplaintDetails(complaint);
      }
    });
  }

  function generateNegligenceSummary(complaint) {
    const today = new Date().toLocaleDateString();
    const inst = complaint.institution || 'the responding institution';
    const dept = complaint.contactPerson ? `${inst}, ${complaint.contactPerson}` : inst;
    const freq = complaint.expectedResponseFrequency || 'regular updates';
    const last = complaint.lastResponseDate ? new Date(complaint.lastResponseDate).toLocaleDateString() : 'N/A';
    const agreed = complaint.agreedTerms || 'prior agreement to accept and process further complaints';
    const lines = [];
    lines.push(`As of ${today}, the responding institution (${dept}) has failed to meet its agreed duty of ${freq}. The last update was received on ${last}.`);
    lines.push('');
    lines.push(`Additionally, despite ${agreed}, this process has been obstructed without cause or explanation.`);
    downloadBlob(lines.join('\n'), `${complaint.id}-summary.txt`, 'text/plain');
  }

  function monthsSinceText(iso) {
    if (!iso) return '';
    const now = new Date().toISOString().slice(0,10);
    const d1 = new Date(iso), d2 = new Date(now);
    let m = (d2.getFullYear() - d1.getFullYear()) * 12 + (d2.getMonth() - d1.getMonth());
    if (d2.getDate() < d1.getDate()) m -= 1;
    m = Math.max(0, m);
    return `${m} month${m===1?'':'s'}`;
  }

  function showLinkedSar(sarId) {
    const sar = Data.sars.find(s => s.id === sarId);
    // Switch to tab
    qsa(".tab").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === "linked-sar"));
    qsa(".panel").forEach(p => p.classList.remove("active"));
    const panel = qs("#panel-linked-sar");
    panel.classList.add("active");
    if (!sar) { panel.innerHTML = `<div class="card">No SAR found: ${sarId}</div>`; return; }
    const due = sar.dateFiled ? new Date(new Date(sar.dateFiled).getTime() + 28*24*60*60*1000) : null;
    const overdue = due && new Date() > due;
    panel.innerHTML = `
      <div class="card">
        <div class="section-title">Linked SAR</div>
        <div><strong>${sar.title}</strong></div>
        <div class="list-meta">${sar.institution} • Filed: ${fmtDate(sar.dateFiled)} • Status: ${sar.status||''}</div>
        <div class="list-meta">Due: ${due?due.toLocaleDateString():'N/A'} ${overdue?'<span class="chip status-red">Overdue</span>':''}</div>
        <div style="margin-top:8px;">${sar.summary || ""}</div>
        <div class="form-actions" style="margin-top:10px;">
          <button class="btn" id="icoEscBtn">Escalate to ICO</button>
          <button class="btn secondary" id="sarDoneBtn">Mark Completed</button>
          <button class="btn secondary" id="sarMissedBtn">Log Missed Response</button>
          <button class="btn secondary" id="sarSetIcoRefBtn">Set ICO Ref</button>
        </div>
        <div class="list-meta">ICO Ref: <span id="icoRefSpan">${sar.icoRef||'—'}</span></div>
      </div>
    `;
    qs('#icoEscBtn').addEventListener('click', () => openIcoTemplateModal(sar));
    qs('#sarDoneBtn').addEventListener('click', () => { sar.status='Completed'; Data.save(); showLinkedSar(sarId); });
    qs('#sarMissedBtn').addEventListener('click', () => { sar.logs = sar.logs||[]; sar.logs.push({ date: new Date().toISOString().slice(0,10), event: 'Missed response logged' }); sar.status = sar.status||'Pending'; Data.save(); showLinkedSar(sarId); });
    qs('#sarSetIcoRefBtn').addEventListener('click', () => { const ref = prompt('ICO Reference: ', sar.icoRef||'')||''; sar.icoRef = ref; Data.save(); showLinkedSar(sarId); });
  }

  function showPhsoTab(complaintId) {
    // Switch tab
    qsa(".tab").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === "phso"));
    qsa(".panel").forEach(p => p.classList.remove("active"));
    const panel = qs('#panel-phso');
    panel.classList.add('active');
    const phso = Data.phsoCases.find(p => p.complaintId === complaintId);
    if (!phso) { panel.innerHTML = `<div class="card">No PHSO case for complaint ${complaintId}</div>`; return; }
    panel.innerHTML = `
      <div class="card">
        <div class="section-title">PHSO Case</div>
        <div><strong>${phso.id}</strong> — for complaint <span class="mono">${phso.complaintId}</span></div>
        <div class="list-meta">Status: ${phso.status}</div>
        <div style="margin-top:8px;">${phso.summary}</div>
      </div>
      <div class="card">
        <div class="section-title">Submitted Evidence</div>
        <div class="stack" id="phsoEvidence"></div>
        <div class="form-actions" style="margin-top:10px;">
          <button class="btn" id="phsoExportBundleBtn">Export Bundle (JSON + files)</button>
          <button class="btn secondary" id="phsoReportBtn">Download Report</button>
        </div>
      </div>
    `;
    (async () => {
      const listEl = qs('#phsoEvidence');
      const files = await Data.listFiles(complaintId);
      if (!files.length) { listEl.innerHTML = '<div class="list-item"><div>No evidence</div></div>'; return; }
      for (const f of files) {
        const row = document.createElement('div');
        row.className = 'list-item';
        row.innerHTML = `<div>${f.name}</div><div><button class="btn secondary" data-key="${f.key}">Download</button></div>`;
        listEl.appendChild(row);
      }
      listEl.addEventListener('click', async (e) => {
        const btn = e.target.closest('button[data-key]');
        if (!btn) return;
        const item = await Data.getFile(btn.getAttribute('data-key'));
        if (!item) return;
        const blob = new Blob([item.data], { type: item.type || 'application/octet-stream' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url; a.download = item.name; a.click();
        setTimeout(() => URL.revokeObjectURL(url), 500);
      });
    })();

    // Export bundle: compile complaint, concerns, responses, and file blobs (base64)
    qs('#phsoExportBundleBtn').addEventListener('click', async () => {
      const comp = Data.getComplaint(complaintId);
      const bundle = { meta: { generatedAt: new Date().toISOString() }, complaint: comp, files: [] };
      const allFileEntries = await Data.listFiles(complaintId);
      for (const f of allFileEntries) {
        const item = await Data.getFile(f.key);
        if (!item) continue;
        bundle.files.push({ key: f.key, name: f.name, type: f.type, size: f.size, base64: arrayBufferToBase64(item.data) });
      }
      downloadBlob(JSON.stringify(bundle, null, 2), `${complaintId}-bundle.json`);
    });

    // Report: simple text report covering complaint + concerns + responses + notes
    qs('#phsoReportBtn').addEventListener('click', async () => {
      const comp = Data.getComplaint(complaintId);
      const lines = [];
      lines.push(`# Complaint Report: ${comp.title}`);
      lines.push(`ID: ${comp.id}`);
      lines.push(`Institution: ${comp.institution}`);
      lines.push(`Date Filed: ${comp.dateFiled}`);
      lines.push(`Status: ${comp.status}`);
      lines.push('');
      lines.push('## Complaint Content');
      lines.push(comp.complaintContent || '');
      lines.push('');
      lines.push('## Concerns');
      (comp.concerns||[]).forEach((c, idx) => {
        lines.push(`### Concern ${idx+1}: ${c.summary}`);
        lines.push(c.details || '');
        lines.push(`Decision Maker: ${c.decisionMaker||''}`);
        lines.push(`Response Date: ${c.responseDate||''}`);
        lines.push(`Evidence URLs: ${(c.evidence||[]).join(', ')}`);
        lines.push('');
        if (Array.isArray(c.notes) && c.notes.length) {
          lines.push('Notes:');
          c.notes.forEach(n => lines.push(`- ${n.date||''} ${n.text||''} ${(n.urls||[]).join(', ')}`));
          lines.push('');
        }
        if (Array.isArray(c.responses) && c.responses.length) {
          lines.push('Responses:');
          c.responses.forEach(r => {
            lines.push(`- ${r.date||''} ${r.decisionMaker||''}: ${r.text||''}`);
            if ((r.urls||[]).length) lines.push(`  URLs: ${(r.urls||[]).join(', ')}`);
          });
          lines.push('');
        }
      });
      downloadBlob(lines.join('\n'), `${complaintId}-report.txt`, 'text/plain');
    });
  }

  async function autoCreatePhsoCase(complaint) {
    // If already exists, skip
    if (Data.phsoCases.find(p => p.complaintId === complaint.id)) return;
    const phso = {
      id: Data.nextPhsoId(),
      complaintId: complaint.id,
      createdAt: new Date().toISOString(),
      status: 'Submitted',
      summary: `Auto-created PHSO submission for complaint ${complaint.id}: ${complaint.title}`
    };
    Data.phsoCases.push(phso);
    await appendHistory(complaint, `PHSO case created: ${phso.id}`);
    Data.upsertComplaint(complaint);
    Data.save();
  }

  async function autoCreateLegalCase(complaint, triggerNote = 'Legal escalation recorded') {
    if (Data.legalCases.find(l => l.complaintId === complaint.id)) return;
    const legal = {
      id: Data.nextLegalId(),
      complaintId: complaint.id,
      createdAt: new Date().toISOString(),
      status: 'Instructed',
      summary: `${triggerNote} for complaint ${complaint.id}: ${complaint.title}`,
      actions: []
    };
    Data.legalCases.push(legal);
    await appendHistory(complaint, `Legal case created: ${legal.id}`);
    Data.upsertComplaint(complaint);
    Data.save();
  }

  function showLegalTab(complaintId) {
    qsa(".tab").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === "legal"));
    qsa(".panel").forEach(p => p.classList.remove("active"));
    const panel = qs('#panel-legal');
    panel.classList.add('active');
    const legal = Data.legalCases.find(l => l.complaintId === complaintId);
    if (!legal) { panel.innerHTML = `<div class="card">No Legal case for complaint ${complaintId}</div>`; return; }
    panel.innerHTML = `
      <div class="card">
        <div class="section-title">Legal Case</div>
        <div><strong>${legal.id}</strong> — for complaint <span class="mono">${legal.complaintId}</span></div>
        <div class="list-meta">Status: ${legal.status}</div>
        <div style="margin-top:8px;">${legal.summary}</div>
        <div class="form-actions" style="margin-top:10px;">
          <button class="btn secondary" id="addLegalActionBtn">Add Legal Action</button>
        </div>
      </div>
      <div class="card">
        <div class="section-title">Actions</div>
        <div class="stack" id="legalActions"></div>
      </div>
    `;
    const actionsEl = qs('#legalActions');
    const renderActions = () => {
      actionsEl.innerHTML = (legal.actions||[]).map(a => `<div class="list-item"><div>${fmtDate(a.date)||''} — ${a.type||'Action'}: ${a.note||''}</div></div>`).join('') || '<div class="list-item"><div>No actions</div></div>';
    };
    renderActions();
    qs('#addLegalActionBtn').addEventListener('click', async () => {
      const type = prompt('Action type (e.g., Pre-Action, Claim Filed, Hearing):') || 'Action';
      const date = prompt('Action date (YYYY-MM-DD):') || '';
      const note = prompt('Notes:') || '';
      legal.actions.push({ type, date, note });
      Data.save();
      renderActions();
    });
  }

  function bindGlobalActions() {
    qs("#refreshBtn").addEventListener("click", renderAll);
    qs('#serverModeToggle').addEventListener('change', async (e) => {
      if (!Server.token) {
        alert('Login first to use Server Mode.');
        e.target.checked = false;
        return;
      }
      if (e.target.checked) {
        await Data.syncFromServer();
        renderAll();
      }
    });
    qs('#loginBtn').addEventListener('click', async () => {
      const username = prompt('API username:');
      const password = prompt('API password:');
      if (!username || !password) return;
      try {
        const res = await fetch(`${Server.baseUrl}/auth/login`, { method: 'POST', headers: { 'Content-Type':'application/json' }, body: JSON.stringify({ username, password }) });
        const data = await res.json();
        if (!res.ok) throw new Error(data.detail || 'Login failed');
        Server.token = data.access_token;
        alert('Logged in. You can toggle Server Mode now.');
      } catch (e) {
        alert(String(e));
      }
    });
    qs("#exportJsonBtn").addEventListener("click", () => {
      const bundle = { complaints: Data.complaints, sars: Data.sars, phso: Data.phsoCases, legal: Data.legalCases, exportedAt: new Date().toISOString() };
      downloadBlob(JSON.stringify(bundle, null, 2), `complaints-export-${Date.now()}.json`);
    });
    qs('#downloadTestBtn').addEventListener('click', async () => {
      // Build a portable test bundle without IndexedDB file blobs
      const resC = await fetch('data/complaints.json').then(r => r.json()).catch(()=>[]);
      const resS = await fetch('data/sars.json').then(r => r.json()).catch(()=>[]);
      const test = { complaints: resC, sars: resS, phso: [], legal: [], exportedAt: new Date().toISOString(), note: 'Test dataset: bundled files only' };
      downloadBlob(JSON.stringify(test, null, 2), 'complaints-test-dataset.json');
    });
    qs('#importJsonBtn').addEventListener('click', () => qs('#importFileInput').click());
    qs('#importFileInput').addEventListener('change', async (e) => {
      const file = e.target.files && e.target.files[0];
      if (!file) return;
      try {
        const text = await file.text();
        const bundle = JSON.parse(text);
        if (Array.isArray(bundle.complaints)) Data.complaints = bundle.complaints;
        if (Array.isArray(bundle.sars)) Data.sars = bundle.sars;
        if (Array.isArray(bundle.phso)) Data.phsoCases = bundle.phso;
        if (Array.isArray(bundle.legal)) Data.legalCases = bundle.legal;
        Data.save();
        renderAll();
        alert('Import complete.');
      } catch (err) {
        console.error(err);
        alert('Invalid JSON file.');
      } finally {
        e.target.value = '';
      }
    });
    qs("#printPdfBtn").addEventListener("click", () => window.print());
    const exportCsvBtn = qs('#exportCsvBtn');
    if (exportCsvBtn) exportCsvBtn.addEventListener('click', () => exportComplaintsCsv(Data.complaints));
    const exportListCsvBtn = qs('#exportListCsvBtn');
    if (exportListCsvBtn) exportListCsvBtn.addEventListener('click', () => exportComplaintsCsv(Data.complaints));
    const exportIcsBtn = qs('#exportIcsBtn');
    if (exportIcsBtn) exportIcsBtn.addEventListener('click', () => exportCalendarIcs());
    // Redacted exports
    const expJson = qs('#exportJsonBtn');
    expJson?.addEventListener('contextmenu', (e) => {
      e.preventDefault();
      const redact = confirm('Export REDACTED JSON? Click Cancel for normal.');
      if (redact) {
        const bundle = { complaints: Data.complaints.map(c => redactComplaintDeep(c)), exportedAt: new Date().toISOString(), redacted: true };
        downloadBlob(JSON.stringify(bundle, null, 2), `complaints-export-redacted-${Date.now()}.json`);
      } else {
        const bundle = { complaints: Data.complaints, sars: Data.sars, phso: Data.phsoCases, legal: Data.legalCases, exportedAt: new Date().toISOString() };
        downloadBlob(JSON.stringify(bundle, null, 2), `complaints-export-${Date.now()}.json`);
      }
    });
  }

  function exportCalendarIcs() {
    const lines = ['BEGIN:VCALENDAR','VERSION:2.0','PRODID:-//ComplaintsTracker//EN'];
    const pushEvent = (summary, dateStr, uid) => {
      if (!dateStr) return;
      const dt = dateStr.replace(/-/g,'');
      lines.push('BEGIN:VEVENT');
      lines.push(`UID:${uid || Math.random().toString(36).slice(2)}@complaintstracker`);
      lines.push(`DTSTART;VALUE=DATE:${dt}`);
      lines.push(`SUMMARY:${summary}`);
      lines.push('END:VEVENT');
    };
    for (const c of Data.complaints) {
      const basis = c.refusalDate || c.eventDate || c.dateFiled;
      if (basis) {
        const d = new Date(basis);
        const phso = new Date(d); phso.setFullYear(d.getFullYear()+1);
        pushEvent(`PHSO deadline for ${c.id}: ${c.title}`, phso.toISOString().slice(0,10), `${c.id}-phso`);
        if (c.eventDate) {
          const ed = new Date(c.eventDate); const legal = new Date(ed); legal.setFullYear(ed.getFullYear()+3);
          pushEvent(`Legal limitation for ${c.id}: ${c.title}`, legal.toISOString().slice(0,10), `${c.id}-legal`);
        }
      }
      if (c.expectedResponseFrequency && (c.lastResponseDate || c.dateFiled)) {
        const base = new Date(c.lastResponseDate || c.dateFiled);
        const next = new Date(base);
        if (c.expectedResponseFrequency === 'Weekly') next.setDate(base.getDate()+7);
        if (c.expectedResponseFrequency === 'Monthly') next.setMonth(base.getMonth()+1);
        if (c.expectedResponseFrequency === 'Quarterly') next.setMonth(base.getMonth()+3);
        pushEvent(`Next expected update for ${c.id}: ${c.title}`, next.toISOString().slice(0,10), `${c.id}-next`);
      }
    }
    lines.push('END:VCALENDAR');
    downloadBlob(lines.join('\n'), `complaints-calendar-${Date.now()}.ics`, 'text/calendar');
  }

  function suggestEscalationPath(type) {
    const map = {
      'NHS': ['PHSO'],
      'Police': ['IOPC'],
      'Data': ['ICO'],
      'Regulator': ['PSA'],
      'SAR Delay': ['ICO']
    };
    return map[type] || ['Unknown'];
  }

  function openEscalationTemplateModal(complaint) {
    const root = qs('#modalRoot'); if (!root) return;
    const path = suggestEscalationPath(complaint.type||'');
    const target = path[0] || 'Regulator';
    const body = `Dear ${complaint.institution||'Sir/Madam'},\n\nI wish to escalate complaint ${complaint.id} (${complaint.title}).\nSummary:\n- ${complaint.complaintContent||''}\n\nPlease acknowledge and advise next steps.\n\nKind regards`;
    root.innerHTML = `
      <div class="modal-backdrop" id="escTplModal">
        <div class="modal">
          <div class="modal-header"><div class="section-title">Escalation Template — ${target}</div><button class="btn secondary" id="escTplClose">Close</button></div>
          <div class="modal-body"><div class="form"><div class="form-row"><label>To<input id="escTo" placeholder="email@example.org" /></label><label>Subject<input id="escSub" value="Escalation: ${complaint.id}" /></label></div><div class="form-row"><label>Body<textarea id="escBody" rows="8">${body}</textarea></label></div></div></div>
          <div class="modal-footer form-actions"><button class="btn" id="escMail">Open Email</button><button class="btn secondary" id="escCopy">Copy</button></div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#escTplClose').addEventListener('click', close);
    qs('#escTplModal').addEventListener('click', (e) => { if (e.target.id === 'escTplModal') close(); });
    qs('#escMail').addEventListener('click', () => { const to=qs('#escTo').value||''; const sub=encodeURIComponent(qs('#escSub').value||''); const b=encodeURIComponent(qs('#escBody').value||''); window.location.href=`mailto:${to}?subject=${sub}&body=${b}`; });
    qs('#escCopy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(qs('#escBody').value||''); alert('Copied'); } catch { alert('Copy failed'); } });
  }

  function openIcoTemplateModal(sar) {
    const root = qs('#modalRoot'); if (!root) return;
    const body = `Dear ICO,\n\nI wish to raise a complaint regarding a SAR submitted to ${sar.institution} on ${fmtDate(sar.dateFiled)}. The organisation has failed to respond within 28 days.\n\nDetails:\n- SAR ID: ${sar.id}\n- Title: ${sar.title}\n- Summary: ${sar.summary||''}\n\nPlease advise the next steps.\n\nKind regards`;
    root.innerHTML = `
      <div class="modal-backdrop" id="icoTplModal">
        <div class="modal">
          <div class="modal-header"><div class="section-title">ICO Escalation Template</div><button class="btn secondary" id="icoTplClose">Close</button></div>
          <div class="modal-body"><div class="form"><div class="form-row"><label>To<input id="icoTo" value="casework@ico.org.uk" /></label><label>Subject<input id="icoSub" value="SAR delay complaint" /></label></div><div class="form-row"><label>Body<textarea id="icoBody" rows="8">${body}</textarea></label></div></div></div>
          <div class="modal-footer form-actions"><button class="btn" id="icoMail">Open Email</button><button class="btn secondary" id="icoCopy">Copy</button></div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#icoTplClose').addEventListener('click', close);
    qs('#icoTplModal').addEventListener('click', (e) => { if (e.target.id === 'icoTplModal') close(); });
    qs('#icoMail').addEventListener('click', () => { const to=qs('#icoTo').value||''; const sub=encodeURIComponent(qs('#icoSub').value||''); const b=encodeURIComponent(qs('#icoBody').value||''); window.location.href=`mailto:${to}?subject=${sub}&body=${b}`; });
    qs('#icoCopy').addEventListener('click', async () => { try { await navigator.clipboard.writeText(qs('#icoBody').value||''); alert('Copied'); } catch { alert('Copy failed'); } });
  }

  function exportComplaintMarkdown(c) {
    const lines = [];
    lines.push(`# ${c.title}`);
    lines.push(`ID: ${c.id}`);
    lines.push(`Type: ${c.type||''}`);
    lines.push(`Institution: ${c.institution}`);
    lines.push(`Date Filed: ${c.dateFiled}`);
    lines.push(`Status: ${c.status}`);
    lines.push('');
    lines.push('## Timeline');
    (c.history||[]).forEach(h => lines.push(`- ${h.date||''} ${h.event||''}`));
    lines.push('');
    lines.push('## Concerns');
    (c.concerns||[]).forEach((cc, i) => { lines.push(`### ${i+1}. ${cc.summary}`); if (cc.details) lines.push(cc.details); });
    downloadBlob(lines.join('\n'), `${c.id}.md`, 'text/markdown');
  }

  function exportComplaintNotebook(c) {
    const nb = { cells: [
      { cell_type: 'markdown', metadata: {}, source: [`# ${c.title}\nID: ${c.id}\nType: ${c.type||''}\nInstitution: ${c.institution}\nStatus: ${c.status}\n`] },
      { cell_type: 'markdown', metadata: {}, source: ['## Timeline\n', ...(c.history||[]).map(h=>`- ${h.date||''} ${h.event||''}\n`)] },
      { cell_type: 'code', metadata: {}, execution_count: null, outputs: [], source: [`log = ${JSON.stringify(c, null, 2)}\nprint('Entries:', len(log.get('concerns', [])))\n`] }
    ], metadata: { kernelspec: { display_name: 'Python 3', name: 'python3' } }, nbformat: 4, nbformat_minor: 5 };
    downloadBlob(JSON.stringify(nb, null, 2), `${c.id}.ipynb`, 'application/json');
  }

  function shareStandaloneComplaint(complaint, redacted) {
    const data = redacted ? redactComplaintDeep(complaint) : complaint;
    const doc = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>Complaint ${data.id}${redacted?' (Redacted)':''}</title><style>body{font:14px system-ui;margin:16px} .card{border:1px solid #ccc;border-radius:8px;padding:12px;margin:8px 0} .list{display:grid;gap:8px} .list-item{border:1px solid #eee;border-radius:6px;padding:8px} .muted{color:#666}</style></head><body><h2>Complaint ${data.id}${redacted?' (Redacted)':''}</h2><div class="card"><div><strong>${data.title}</strong></div><div class="muted">${data.institution||''} • ${data.status||''} • ${data.dateFiled||''}</div><div style="margin-top:8px;">${data.complaintContent||''}</div></div><div class="card"><div><strong>Concerns</strong></div><div class="list">${(data.concerns||[]).map(c => `<div class=\"list-item\"><div><strong>${c.summary||''}</strong></div><div class=\"muted\">Decision: ${c.decisionMaker||'—'} • ${c.responseDate||''}</div><div>${c.details||''}</div></div>`).join('')||'<div class=\"list-item\">None</div>'}</div></div><div class="card"><div class="muted">Generated ${new Date().toLocaleString()}</div></div><script>/* offline */</script></body></html>`;
    const blob = new Blob([doc], { type: 'text/html' });
    const url = URL.createObjectURL(blob);
    window.open(url, '_blank');
  }

  function exportComplaintsCsv(list) {
    const headers = ['ID','Title','Institution','Date Filed','Status'];
    const rows = list.map(c => [c.id, c.title, c.institution||'', (c.dateFiled||'').slice(0,10), c.status||'']);
    const csv = [headers.join(','), ...rows.map(r => r.map(v => {
      const s = String(v||'');
      return (/[",\n]/.test(s)) ? '"' + s.replace(/"/g,'""') + '"' : s;
    }).join(','))].join('\n');
    downloadBlob(csv, `complaints-${Date.now()}.csv`, 'text/csv');
  }

  function renderActionRequired() {
    const card = qs('#actionRequiredCard');
    const listEl = qs('#actionRequiredContainer');
    if (!card || !listEl) return;
    const items = [];
    const today = new Date();
    for (const c of Data.complaints) {
      const basis = c.refusalDate || c.eventDate || c.dateFiled;
      if (basis) {
        const d = new Date(basis);
        const phsoDeadline = new Date(d); phsoDeadline.setFullYear(d.getFullYear()+1);
        if (today > phsoDeadline && !/(phso|ombudsman)/i.test(c.status||'')) {
          items.push({ c, kind: 'PHSO', text: `PHSO deadline passed (${phsoDeadline.toLocaleDateString()}). Consider escalating.` });
        }
      }
      if (c.eventDate) {
        const d = new Date(c.eventDate);
        const legalDeadline = new Date(d); legalDeadline.setFullYear(d.getFullYear()+3);
        if (today > legalDeadline && !/(legal|claim|court|litig)/i.test(c.status||'')) {
          items.push({ c, kind: 'LEGAL', text: `Legal limitation expired (${legalDeadline.toLocaleDateString()}). Seek advice.` });
        }
      }
      const last = c.lastResponseDate || c.dateFiled;
      if (last) {
        const days = Math.floor((today - new Date(last)) / (1000*60*60*24));
        if (days >= 30 && !/(responded|resolved|closed)/i.test(c.status||'')) {
          items.push({ c, kind: 'STALE', text: `${days} days since last response. Send chaser.` });
        }
      }
    }
    if (!items.length) { card.style.display = 'none'; listEl.innerHTML = ''; return; }
    card.style.display = '';
    listEl.innerHTML = items.map(it => `
      <div class="list-item action">
        <div>
          <div><strong>${it.c.title}</strong></div>
          <div class="list-meta">${it.text}</div>
        </div>
        <div class="form-actions">
          <button class="btn secondary" data-open="${it.c.id}">Open</button>
          <button class="btn" data-phso="${it.c.id}">Send to PHSO</button>
          <button class="btn secondary" data-acc="${it.c.id}">Accountability</button>
          <button class="btn secondary" data-chaser="${it.c.id}">Chaser</button>
        </div>
      </div>
    `).join('');
    listEl.onclick = (e) => {
      const open = e.target.closest('button[data-open]');
      const phso = e.target.closest('button[data-phso]');
      const acc = e.target.closest('button[data-acc]');
      const ch = e.target.closest('button[data-chaser]');
      if (open) { const c = Data.getComplaint(open.getAttribute('data-open')); if (c) showComplaintDetails(c); }
      if (phso) { const c = Data.getComplaint(phso.getAttribute('data-phso')); if (c) { c.status = 'Escalated to PHSO'; appendHistory(c,'Escalated via Action Required'); Data.upsertComplaint(c); autoCreatePhsoCase(c).then(()=>showPhsoTab(c.id)); } }
      if (acc) { const c = Data.getComplaint(acc.getAttribute('data-acc')); if (c) {
        const subject = c.contactPerson || c.institution || 'Unnamed Subject';
        const entry = { id: `subj_${Math.random().toString(36).slice(2,7)}`, subject, role: 'Contact/Institution', organisation: c.institution||'', status: 'Open', allegations: '', harm: [], evidence: [], dates: [c.dateFiled].filter(Boolean), linkedComplaints: [c.id] };
        Data.accountability.push(entry); Data.save(); alert('Sent to Accountability.'); qsa('.tab').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === 'accountability')); qsa('.panel').forEach(p => p.classList.remove('active')); qs('#panel-accountability').classList.add('active'); renderAccountability();
      } }
      if (ch) { const c = Data.getComplaint(ch.getAttribute('data-chaser')); if (c) openChaserModal(c); }
    };
  }

  function renderAll() {
    renderFilters();
    computeMetrics();
    renderComplaintsList();
    renderOpenEntries();
    renderSearch();
    populateLinkedSarSelect();
    populateInstitutionSelect();
    if (qs('#panel-legal')) renderLegalOverview();
    renderAccountability();
    renderCalendar();
    renderDetailsPlaceholder();
    renderResources();
    computeWarnings();
    renderActionRequired?.();
  }

  function renderOpenEntries() {
    const container = qs('#openEntriesContainer'); if (!container) return;
    const entries = [
      ...Data.complaints.map(c => ({ kind: 'Complaint', title: c.title, date: c.dateFiled, status: c.status, id: c.id })),
      ...Data.sars.map(s => ({ kind: 'SAR', title: s.title, date: s.dateFiled, status: s.status, id: s.id }))
    ].filter(e => !/(resolved|closed)/i.test(e.status||''));
    container.innerHTML = entries.map(e => `<div class="list-item"><div><div><strong>${e.title}</strong></div><div class="list-meta">${e.kind} • ${fmtDate(e.date)} • ${e.status||''}</div></div><div><button class="btn secondary" data-open="${e.kind}:${e.id}">Open</button></div></div>`).join('') || '<div class="list-item"><div>No open entries</div></div>';
    container.onclick = (ev) => {
      const btn = ev.target.closest('button[data-open]'); if (!btn) return;
      const [kind,id] = btn.getAttribute('data-open').split(':');
      if (kind==='Complaint') { const c = Data.getComplaint(id); if (c) showComplaintDetails(c); }
      if (kind==='SAR') { showLinkedSar(id); }
    };
  }

  function renderLegalOverview() {
    const panel = qs('#panel-legal');
    if (!panel || !panel.classList.contains('active')) return; // only render when visible and present
    const container = qs('#legalContainer');
    const items = Data.legalCases.map(l => {
      const c = Data.getComplaint(l.complaintId) || { title: l.complaintId };
      return `<div class="list-item"><div><strong>${l.id}</strong> — ${c.title}<div class="list-meta">${l.status} • ${new Date(l.createdAt).toLocaleString()}</div></div><div><button class="btn secondary" data-cid="${l.complaintId}">Open</button></div></div>`;
    }).join('') || '<div class="list-item"><div>No legal cases</div></div>';
    container.innerHTML = `<div class="list-header"><div>Legal Cases</div></div><div class="list">${items}</div>`;
    container.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-cid]');
      if (!btn) return;
      showLegalTab(btn.getAttribute('data-cid'));
    }, { once: true });
  }

  // Simple local auth (demo): admin login and per-user sessions
  function setupSecureLogin() {
    const secureLoginBtn = qs('#secureLoginBtn');
    const logoutBtn = qs('#logoutBtn');
    const updateUi = () => {
      const logged = !!(Data.session && Data.session.user);
      if (logoutBtn) logoutBtn.style.display = logged ? '' : 'none';
    };
    if (secureLoginBtn) secureLoginBtn.addEventListener('click', () => openAuthModal('login'));
    if (logoutBtn) logoutBtn.addEventListener('click', () => {
      Data.session.user = null; Data.save(); updateUi(); alert('Logged out');
      renderAll();
      if (!(Data.session && Data.session.user)) injectDemoData();
    });
    updateUi();
  }

  function openAuthModal(initialMode = 'login') {
    const root = qs('#modalRoot'); if (!root) return;
    let mode = initialMode; // 'login' | 'signup'
    const render = () => {
      root.innerHTML = `
        <div class="modal-backdrop" id="authModal">
          <div class="modal">
            <div class="modal-header">
              <div class="section-title">Secure ${mode === 'login' ? 'Login' : 'Sign Up'}</div>
              <div class="form-actions">
                <button class="btn secondary" id="switchToLogin">Login</button>
                <button class="btn secondary" id="switchToSignup">Sign Up</button>
                <button class="btn secondary" id="authClose">Close</button>
              </div>
            </div>
            <div class="modal-body">
              <div class="form">
                <div class="form-row">
                  <label>Username<input id="authUsername" placeholder="Username" /></label>
                  <label>Password<input id="authPassword" type="password" placeholder="Password" /></label>
                </div>
              </div>
            </div>
            <div class="modal-footer form-actions">
              <button class="btn" id="authPrimary">${mode === 'login' ? 'Login' : 'Create Account'}</button>
              <button class="btn secondary" id="authCancel">Cancel</button>
            </div>
          </div>
        </div>
      `;
      const close = () => { root.innerHTML = ''; };
      qs('#authClose').addEventListener('click', close);
      qs('#authCancel').addEventListener('click', close);
      qs('#authModal').addEventListener('click', (e) => { if (e.target.id === 'authModal') close(); });
      qs('#switchToLogin').addEventListener('click', () => { mode = 'login'; render(); });
      qs('#switchToSignup').addEventListener('click', () => { mode = 'signup'; render(); });
      qs('#authPrimary').addEventListener('click', async () => {
        const username = (qs('#authUsername').value || '').trim();
        const password = (qs('#authPassword').value || '').trim();
        if (!username || !password) { alert('Enter username and password'); return; }
        if (mode === 'signup') {
          if (Data.users.find(u => u.username === username)) { alert('User exists'); return; }
          Data.users.push({ username, password, createdAt: new Date().toISOString() });
          Data.save(); alert('User created. You can login now.'); mode = 'login'; render(); return;
        }
        // login
        if (username === 'admin' && password === 'admin123') {
          Data.session.user = { username: 'admin', role: 'admin' };
          // Load bundled dataset for admin view and clear any demo-only in-memory data
          try { await Data._loadFromFiles(); } catch {}
          // Restore persisted accountability (demo was not saved)
          try { Data.accountability = JSON.parse(localStorage.getItem(STORAGE_KEYS.accountability) || '[]'); } catch { Data.accountability = []; }
          Data.save();
          close();
          // Switch to All Complaints and render
          qsa('.tab').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === 'all'));
          qsa('.panel').forEach(p => p.classList.remove('active'));
          qs('#panel-all').classList.add('active');
          Data.reloadForCurrentUser(); renderAll();
          alert('Logged in as admin');
          return;
        }
        const user = Data.users.find(u => u.username === username && u.password === password);
        if (!user) { alert('Invalid credentials'); return; }
        Data.session.user = { username, role: 'user' };
        Data.save(); Data.reloadForCurrentUser();
        close();
        renderAll();
        alert('Logged in');
      });
    };
    render();
  }

  function requireLogin() {
    if (!(Data.session && Data.session.user)) { alert('Login required to access this area.'); return false; }
    return true;
  }

  // Accountability: subjects (individual/institution), role, org, allegations, harm, evidence, incident dates, linked cases, status
  function renderAccountability() {
    const panel = qs('#panel-accountability');
    if (!panel || !panel.classList.contains('active')) return;
    const container = qs('#accountabilityContainer');
    const list = Data.accountability || [];
    const searchInput = qs('#accSearchInput');
    const filterList = () => {
      const q = (searchInput?.value||'').toLowerCase();
      return list.filter(s => !q || JSON.stringify(s).toLowerCase().includes(q));
    };
    const sorted = (function(){
      const arr = filterList().slice();
      const key = accSort.key; const dir = accSort.dir === 'asc' ? 1 : -1;
      arr.sort((a,b) => String(a[key]||'').localeCompare(String(b[key]||'')) * dir);
      return arr;
    })();
    const rows = (sorted).map(s => `
      <tr>
        <td>${s.subject}</td>
        <td>${s.organisation||''}</td>
        <td>${s.role||''}</td>
        <td>${(s.chargeType||'').toString()}</td>
        <td>${(s.linkedComplaints||[]).join(', ')||'—'}</td>
        <td>${s.status||'Open'}</td>
        <td><button class="btn secondary" data-action="open" data-id="${s.id}">Open</button></td>
      </tr>
    `).join('');
    container.innerHTML = `
      <div class="card">
        <table class="table">
          <thead>
            <tr>
              <th data-sort="subject">Person/Subject</th>
              <th data-sort="organisation">Institution</th>
              <th data-sort="role">Role</th>
              <th data-sort="chargeType">Charge</th>
              <th>Linked</th>
              <th data-sort="status">Status</th>
              <th></th>
            </tr>
          </thead>
          <tbody>${rows || '<tr><td colspan="7">No accountability subjects</td></tr>'}</tbody>
        </table>
      </div>
      <div class="list-header">
        <div>Subjects</div>
        <div class="list-actions">
          <button class="btn secondary" id="accAddBtn">+ Add Entry</button>
          <button class="btn secondary" id="accExportBtn">Master Report Export</button>
        </div>
      </div>
    `;
    if (searchInput) { searchInput.oninput = () => renderAccountability(); }
    qs('#accClearBtn')?.addEventListener('click', () => { if (searchInput) searchInput.value = ''; renderAccountability(); });
    const thead = container.querySelector('thead');
    if (thead) {
      thead.onclick = (e) => {
        const th = e.target.closest('th[data-sort]');
        if (!th) return;
        const key = th.getAttribute('data-sort');
        if (accSort.key === key) accSort.dir = accSort.dir === 'asc' ? 'desc' : 'asc'; else { accSort.key = key; accSort.dir = 'asc'; }
        renderAccountability();
      };
    }
    container.addEventListener('click', (e) => {
      const btn = e.target.closest('button[data-action]');
      if (!btn) return;
      if (!requireLogin()) return;
      const id = btn.getAttribute('data-id');
      const action = btn.getAttribute('data-action');
      if (action === 'open' && id) openAccountabilityDetail(id);
    }, { once: true });
    qs('#accAddBtn')?.addEventListener('click', () => { if (!requireLogin()) return; openAccountabilityModal(); });
    qs('#accExportBtn')?.addEventListener('click', () => { if (!requireLogin()) return; exportAccountabilityMaster(); });
  }

  function openAccountabilityModal(existing) {
    const root = qs('#modalRoot'); if (!root) return;
    const isEdit = !!existing;
    const id = isEdit ? existing.id : `subj_${Math.random().toString(36).slice(2,7)}`;
    root.innerHTML = `
      <div class="modal-backdrop" id="accModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">${isEdit ? 'Edit Subject' : 'Add Subject'}</div>
            <button class="btn secondary" id="accCancel">Close</button>
          </div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row">
                <label>Subject<input id="accSubject" value="${isEdit?(existing.subject||'').replace(/"/g,'&quot;'):''}" required /></label>
                <label>Role<input id="accRole" value="${isEdit?(existing.role||'').replace(/"/g,'&quot;'):''}" /></label>
              </div>
              <div class="form-row">
                <label>Organisation<input id="accOrg" value="${isEdit?(existing.organisation||'').replace(/"/g,'&quot;'):''}" /></label>
                <label>Status<input id="accStatus" value="${isEdit?(existing.status||'Open').replace(/"/g,'&quot;'):'Open'}" /></label>
              </div>
              <div class="form-row">
                <label>Allegations<textarea id="accAllegations" rows="3">${isEdit?(existing.allegations||''):''}</textarea></label>
              </div>
              <div class="form-row">
                <label>Harm Tags (comma-separated)<input id="accHarm" value="${isEdit?(Array.isArray(existing.harm)?existing.harm.join(', '):''):''}" /></label>
              </div>
              <div class="form-row">
                <label>Evidence URLs (comma-separated)<input id="accUrls" value="${isEdit?(Array.isArray(existing.evidence)?existing.evidence.join(', '):''):''}" /></label>
              </div>
              <div class="form-row">
                <label>Date(s) of Incident<input id="accDates" placeholder="YYYY-MM-DD; YYYY-MM-DD" value="${isEdit?(Array.isArray(existing.dates)?existing.dates.join('; '):''):''}" /></label>
              </div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="accSave">${isEdit?'Save Changes':'Save Entry'}</button>
            <button class="btn secondary" id="accCancel2">Cancel</button>
          </div>
        </div>
      </div>
    `;
    const close = () => { root.innerHTML = ''; };
    qs('#accCancel').addEventListener('click', close);
    qs('#accCancel2').addEventListener('click', close);
    qs('#accModal').addEventListener('click', (e) => { if (e.target.id === 'accModal') close(); });
    qs('#accSave').addEventListener('click', () => {
      if (!requireLogin()) return;
      const subject = (qs('#accSubject').value||'').trim(); if (!subject) { alert('Subject required'); return; }
      const role = (qs('#accRole').value||'').trim();
      const organisation = (qs('#accOrg').value||'').trim();
      const status = (qs('#accStatus').value||'Open').trim();
      const allegations = (qs('#accAllegations').value||'').trim();
      const harm = (qs('#accHarm').value||'').split(',').map(s=>s.trim()).filter(Boolean);
      const evidence = (qs('#accUrls').value||'').split(',').map(s=>s.trim()).filter(Boolean);
      const dates = (qs('#accDates').value||'').split(';').map(s=>s.trim()).filter(Boolean);
      const entry = isEdit ? existing : { id };
      Object.assign(entry, { subject, role, organisation, status, allegations, harm, evidence, dates, linkedComplaints: [] });
      if (!isEdit) Data.accountability.push(entry);
      Data.save(); close(); renderAccountability();
    });
  }

  function openAccountabilityDetail(id) {
    const s = Data.accountability.find(x => x.id === id);
    if (!s) return;
    const root = qs('#modalRoot'); if (!root) return;
    root.innerHTML = `
      <div class="modal-backdrop" id="accDetModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">${s.subject}</div>
            <button class="btn secondary" id="accDetClose">Close</button>
          </div>
          <div class="modal-body">
            <div class="stack">
              <div class="list-item"><div><strong>Role</strong></div><div>${s.role||''}</div></div>
              <div class="list-item"><div><strong>Organisation</strong></div><div>${s.organisation||''}</div></div>
              <div class="list-item"><div><strong>Status</strong></div><div>${s.status||'Open'}</div></div>
              <div class="list-item"><div><strong>Allegations</strong></div><div>${s.allegations||''}</div></div>
              <div class="list-item"><div><strong>Harm</strong></div><div>${(s.harm||[]).join(', ')}</div></div>
              <div class="list-item"><div><strong>Evidence</strong></div><div>${(s.evidence||[]).map(u => u.startsWith('http')?`<a href="${u}" target="_blank" rel="noopener">${u}</a>`:u).join(', ')}</div></div>
              <div class="list-item"><div><strong>Dates</strong></div><div>${(s.dates||[]).join('; ')}</div></div>
              <div class="list-item"><div><strong>Linked Complaints</strong></div><div>${(s.linkedComplaints||[]).join(', ')||'—'}</div></div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="accGenReport">Generate Report</button>
            <button class="btn secondary" id="accEdit">Edit</button>
          </div>
        </div>
      </div>
    `;
    const close = () => { root.innerHTML = ''; };
    qs('#accDetClose').addEventListener('click', close);
    qs('#accGenReport').addEventListener('click', () => {
      const lines = [];
      lines.push(`# Subject Report: ${s.subject}`);
      lines.push(`Role: ${s.role||''}`);
      lines.push(`Organisation: ${s.organisation||''}`);
      lines.push(`Status: ${s.status||'Open'}`);
      lines.push('');
      lines.push('Allegations:');
      lines.push(s.allegations||'');
      lines.push('');
      lines.push(`Harm: ${(s.harm||[]).join(', ')}`);
      lines.push(`Evidence: ${(s.evidence||[]).join(', ')}`);
      lines.push(`Dates: ${(s.dates||[]).join('; ')}`);
      lines.push(`Linked Complaints: ${(s.linkedComplaints||[]).join(', ')}`);
      downloadBlob(lines.join('\n'), `${s.id}-report.txt`, 'text/plain');
    });
    qs('#accEdit').addEventListener('click', () => { const existing = Data.accountability.find(x => x.id === id); close(); openAccountabilityModal(existing); });
  }

  function exportAccountabilityMaster() {
    const grouped = {};
    for (const s of (Data.accountability||[])) {
      const key = s.organisation || 'Unspecified';
      grouped[key] = grouped[key] || [];
      grouped[key].push(s);
    }
    const lines = [];
    lines.push('# Master Accountability Report');
    lines.push(`Generated: ${new Date().toISOString()}`);
    lines.push('');
    Object.keys(grouped).sort().forEach(org => {
      lines.push(`## ${org}`);
      grouped[org].forEach(s => {
        lines.push(`- ${s.subject} — ${s.role||''} [${s.status||'Open'}] Harm: ${(s.harm||[]).join(', ')}`);
      });
      lines.push('');
    });
    downloadBlob(lines.join('\n'), `accountability-master-report.txt`, 'text/plain');
  }

  function renderCalendar() {
    const panel = qs('#panel-calendar');
    if (!panel.classList.contains('active')) return; // only render when visible
    const container = qs('#calendarContainer');
    const allDates = Data.complaints.flatMap(c => (c.history||[]).map(h => h.date).filter(Boolean));
    const minDate = allDates.length ? new Date(allDates.reduce((a,b)=>a<b?a:b)) : null;
    const maxDate = allDates.length ? new Date(allDates.reduce((a,b)=>a>b?a:b)) : null;
    const year = (minDate || new Date()).getFullYear();
    const months = Array.from({ length: 12 }, (_, i) => new Date(year, i, 1));

    const monthHtml = months.map(m => {
      const monthName = m.toLocaleString(undefined, { month: 'long' });
      const daysInMonth = new Date(m.getFullYear(), m.getMonth()+1, 0).getDate();
      const grid = [];
      for (let d=1; d<=daysInMonth; d++) {
        const dateStr = new Date(m.getFullYear(), m.getMonth(), d).toISOString().slice(0,10);
        const hits = Data.complaints.filter(c => (c.history||[]).some(h => h.date === dateStr));
        grid.push(`<div class="cal-day${hits.length? ' cal-hit':''}" title="${dateStr} — ${hits.length} events">${d}</div>`);
      }
      return `<div class="cal-month"><div class="cal-title">${monthName}</div><div class="cal-grid">${grid.join('')}</div></div>`;
    }).join('');

    const timeline = (minDate && maxDate) ? `${minDate.toLocaleDateString()} — ${maxDate.toLocaleDateString()}` : 'No dated events yet';

    container.innerHTML = `
      <div class="card">
        <div class="section-title">Timeline Overview</div>
        <div>${timeline}</div>
      </div>
      <div class="card">
        <div class="section-title">Year View (${year})</div>
        <div class="cal-year">${monthHtml}</div>
      </div>
      <div class="card">
        <div class="section-title">Events</div>
        <div id="calEventsList" class="list"><div class="list-item"><div>Select a day to see events.</div></div></div>
      </div>
    `;

    // Day click → list events
    container.onclick = (e) => {
      const day = e.target.closest('.cal-day');
      if (!day) return;
      const title = day.getAttribute('title') || '';
      const dateStr = title.split(' — ')[0];
      const events = [];
      Data.complaints.forEach(c => {
        (c.history||[]).forEach(h => {
          if (h.date === dateStr) events.push({ complaint: c, history: h });
        });
      });
      const list = qs('#calEventsList');
      if (!events.length) {
        list.innerHTML = '<div class="list-item"><div>No events for this day.</div></div>';
        return;
      }
      list.innerHTML = events.map(ev => `
        <div class="list-item">
          <div>
            <div><strong>${ev.complaint.title}</strong></div>
            <div class="list-meta">${ev.complaint.institution} • ID: <span class="mono">${ev.complaint.id}</span></div>
          </div>
          <div>${ev.history.event}</div>
        </div>
      `).join('');
    };
  }

  async function renderResources() {
    const panel = qs('#panel-resources');
    if (!panel.classList.contains('active')) return; // only render when visible
    const container = qs('#resourcesContainer');
    try {
      const res = await fetch('documents/resource.txt', { cache: 'no-store' });
      if (!res.ok) throw new Error('Missing resource.txt');
      const text = await res.text();
      const lines = text.split(/\r?\n/).map(l => l.trim()).filter(Boolean);
      const items = [];
      for (const line of lines) {
        const match = line.match(/https?:\/\/\S+/);
        if (!match) continue;
        const url = match[0];
        let desc = (line.replace(url, '').trim()).replace(/^[\-–—,:\s]+/, '').trim();
        if (!desc) { try { desc = new URL(url).hostname; } catch { desc = 'Link'; } }
        items.push({ url, desc });
      }
      container.innerHTML = (items.length ? items.map(it => `<div class="list-item"><div>${it.desc} — <a href="${it.url}" target="_blank" rel="noopener">${it.url}</a></div></div>`).join('') : '<div class="list-item"><div>No resources listed</div></div>');
    } catch (e) {
      container.innerHTML = '<div class="list-item"><div>resource.txt not found. Add one under documents/ to populate this section.</div></div>';
    }
    // Counsellors CSV (optional)
    const counsellorsEl = qs('#counsellorsContainer');
    if (counsellorsEl) {
      try {
        const r = await fetch('documents/counsellors.csv', { cache: 'no-store' });
        if (!r.ok) throw new Error('no csv');
        const text = await r.text();
        const lines = text.split(/\r?\n/).filter(Boolean);
        if (lines.length && /,/.test(lines[0])) lines.shift();
        const rows = lines.map(l => l.split(/,(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)/));
        counsellorsEl.innerHTML = rows.slice(0,20).map(cols => `<div class=\"list-item\"><div>${(cols[0]||'Counsellor')}</div><div class=\"list-meta\">${(cols[1]||'')}</div></div>`).join('') || '<div class=\"list-item\"><div>No counsellors listed</div></div>';
      } catch {
        counsellorsEl.innerHTML = '<div class=\"list-item\"><div>Add a CSV at documents/counsellors.csv to populate.</div></div>';
      }
    }
  }

  function openClosureModal(complaint) {
    const root = qs('#modalRoot'); if (!root) return;
    const event = complaint.eventDate ? new Date(complaint.eventDate) : null;
    const refusal = complaint.refusalDate ? new Date(complaint.refusalDate) : null;
    const base = refusal || event || (complaint.dateFiled ? new Date(complaint.dateFiled) : null);
    const phsoDeadline = base ? new Date(base.getFullYear()+1, base.getMonth(), base.getDate()) : null;
    const legalDeadline = event ? new Date(event.getFullYear()+3, event.getMonth(), event.getDate()) : null;
    root.innerHTML = `
      <div class="modal-backdrop" id="closureModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">Closure & Next Steps</div>
            <button class="btn secondary" id="closureClose">Close</button>
          </div>
          <div class="modal-body">
            <div class="stack">
              <div class="list-item"><div><strong>Deadlines</strong></div><div class="list-meta">PHSO: ${phsoDeadline?phsoDeadline.toLocaleDateString():'N/A'} • Legal: ${legalDeadline?legalDeadline.toLocaleDateString():'N/A'}</div></div>
              <div class="list-item"><div><strong>Checklist</strong></div><div class="list-meta">Tick each as you proceed.</div></div>
              <div class="stack" id="closureChecklist">
                <label class="list-item"><div><input type="checkbox" data-step="chaser" /> Sent 14/30-day chaser</div></label>
                <label class="list-item"><div><input type="checkbox" data-step="phso" /> Prepared PHSO submission</div></label>
                <label class="list-item"><div><input type="checkbox" data-step="legal" /> Sought legal advice</div></label>
                <label class="list-item"><div><input type="checkbox" data-step="accountability" /> Logged individuals in Accountability</div></label>
              </div>
              <div class="list-item"><div><strong>Support</strong></div><div><a href="#" id="openResources">Open Resources</a></div></div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="closurePhso">Send to PHSO</button>
            <button class="btn secondary" id="closureAcc">Send to Accountability</button>
          </div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#closureClose').addEventListener('click', close);
    qs('#closureModal').addEventListener('click', (e) => { if (e.target.id === 'closureModal') close(); });
    qs('#openResources').addEventListener('click', (e) => { e.preventDefault(); qsa('.tab').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === 'resources')); qsa('.panel').forEach(p => p.classList.remove('active')); qs('#panel-resources').classList.add('active'); renderResources(); close(); });
    qs('#closurePhso').addEventListener('click', async () => { complaint.status = 'Escalated to PHSO'; await appendHistory(complaint,'Escalated via Closure'); Data.upsertComplaint(complaint); await autoCreatePhsoCase(complaint); showPhsoTab(complaint.id); close(); });
    qs('#closureAcc').addEventListener('click', () => { const subject = complaint.contactPerson || complaint.institution || 'Unnamed Subject'; const entry = { id: `subj_${Math.random().toString(36).slice(2,7)}`, subject, role: 'Contact/Institution', organisation: complaint.institution||'', status: 'Open', allegations: '', harm: [], evidence: [], dates: [complaint.dateFiled].filter(Boolean), linkedComplaints: [complaint.id] }; Data.accountability.push(entry); Data.save(); qsa('.tab').forEach(btn => btn.classList.toggle('active', btn.dataset.tab === 'accountability')); qsa('.panel').forEach(p => p.classList.remove('active')); qs('#panel-accountability').classList.add('active'); renderAccountability(); close(); });
  }

  function openChaserModal(complaint) {
    const root = qs('#modalRoot'); if (!root) return;
    const to = (complaint.institutionEmail||'');
    const subjectDefault = `Request for update: ${complaint.id}`;
    const bodyDefault = `Dear ${complaint.contactPerson||'Sir/Madam'},\n\nPlease provide an update on complaint ${complaint.id} (${complaint.title}) filed on ${fmtDate(complaint.dateFiled)} within 14 days.\n\nKind regards`;
    root.innerHTML = `
      <div class="modal-backdrop" id="chaserModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">Send Chaser</div>
            <button class="btn secondary" id="chaserClose">Close</button>
          </div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row">
                <label>To<input id="chaserTo" value="${to.replace(/\"/g,'&quot;')}" /></label>
                <label>Subject<input id="chaserSubject" value="${subjectDefault.replace(/\"/g,'&quot;')}" /></label>
              </div>
              <div class="form-row">
                <label>Body<textarea id="chaserBody" rows="6">${bodyDefault}</textarea></label>
              </div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="chaserMailto">Open Email</button>
            <button class="btn secondary" id="chaserCopy">Copy to Clipboard</button>
          </div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#chaserClose').addEventListener('click', close);
    qs('#chaserModal').addEventListener('click', (e) => { if (e.target.id === 'chaserModal') close(); });
    qs('#chaserMailto').addEventListener('click', () => {
      const toVal = (qs('#chaserTo').value||'');
      const sub = encodeURIComponent(qs('#chaserSubject').value||'');
      const body = encodeURIComponent(qs('#chaserBody').value||'');
      window.location.href = `mailto:${toVal}?subject=${sub}&body=${body}`;
    });
    qs('#chaserCopy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(qs('#chaserBody').value||''); alert('Copied'); } catch { alert('Copy failed'); }
    });
  }

  function openRedactionControlsModal(complaint) {
    const root = qs('#modalRoot'); if (!root) return;
    const ov = complaint.redactOverrides || {};
    const safe = new Set(ov.safeAttachments||[]);
    root.innerHTML = `
      <div class="modal-backdrop" id="redactModal">
        <div class="modal">
          <div class="modal-header"><div class="section-title">Redaction Controls</div><button class="btn secondary" id="redactClose">Close</button></div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row">
                <label class="chip"><input type="checkbox" id="ovTitle" ${ov.title===false?'':'checked'} /> Title</label>
                <label class="chip"><input type="checkbox" id="ovContent" ${ov.complaintContent===false?'':'checked'} /> Content</label>
                <label class="chip"><input type="checkbox" id="ovInstEmail" ${ov.institutionEmail===false?'':'checked'} /> Institution Email</label>
              </div>
              <div class="section-title">Attachments Safety (include only checked in redacted)</div>
              <div class="stack" id="ovFiles">${(complaint.concerns||[]).flatMap(c => (c.attachments||[])).map(key => `<label class=\"list-item\"><div><input type=\"checkbox\" data-key=\"${key}\" ${safe.has(key)?'checked':''}/> ${key}</div></label>`).join('') || '<div class="list-item"><div>No attachments</div></div>'}</div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="redactSave">Save Overrides</button>
          </div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#redactClose').addEventListener('click', close);
    qs('#redactModal').addEventListener('click', (e) => { if (e.target.id === 'redactModal') close(); });
    qs('#redactSave').addEventListener('click', () => {
      const next = complaint.redactOverrides || {};
      next.title = qs('#ovTitle').checked ? true : false;
      next.complaintContent = qs('#ovContent').checked ? true : false;
      next.institutionEmail = qs('#ovInstEmail').checked ? true : false;
      const keys = Array.from(document.querySelectorAll('#ovFiles input[type="checkbox"][data-key]')).filter(el => el.checked).map(el => el.getAttribute('data-key'));
      next.safeAttachments = keys;
      complaint.redactOverrides = next;
      Data.upsertComplaint(complaint);
      close();
    });
  }

  function openShareConcernsModal(complaint) {
    const root = qs('#modalRoot'); if (!root) return;
    const targets = (complaint.concerns||[]);
    root.innerHTML = `
      <div class="modal-backdrop" id="shareConsModal">
        <div class="modal">
          <div class="modal-header"><div class="section-title">Share Concerns</div><button class="btn secondary" id="shareConsClose">Close</button></div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row"><label>Recipients<select id="regRecipient"><option value="psa">PSA Concerns</option><option value="cqc">CQC Concerns</option><option value="custom">Custom</option></select></label><label>Email<input id="regEmail" placeholder="concerns@example.org" /></label></div>
              <div class="form-row"><label>Summary<textarea id="consSummary" rows="3" placeholder="Short summary of concerns being shared"></textarea></label></div>
              <div class="section-title">Select Concerns</div>
              <div class="stack" id="consList">${targets.map(c => `<label class=\"list-item\"><div><input type=\"checkbox\" data-id=\"${c.id}\"/> ${c.summary}</div></label>`).join('') || '<div class="list-item"><div>No concerns</div></div>'}</div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="consMail">Open Email</button>
            <button class="btn secondary" id="consCopy">Copy Summary</button>
          </div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#shareConsClose').addEventListener('click', close);
    qs('#shareConsModal').addEventListener('click', (e) => { if (e.target.id === 'shareConsModal') close(); });
    const recSel = qs('#regRecipient');
    const emailInput = qs('#regEmail');
    const setEmail = () => {
      const v = recSel.value;
      if (v==='psa') emailInput.value = 'concerns@professionalstandards.org.uk';
      if (v==='cqc') emailInput.value = 'enquiries@cqc.org.uk';
      if (v==='custom') emailInput.value = '';
    };
    recSel.addEventListener('change', setEmail); setEmail();
    const buildText = () => {
      const ids = Array.from(document.querySelectorAll('#consList input[type="checkbox"][data-id]')).filter(el => el.checked).map(el => el.getAttribute('data-id'));
      const chosen = (complaint.concerns||[]).filter(c => ids.includes(c.id));
      const lines = [];
      lines.push(`Summary: ${(qs('#consSummary').value||'').trim()}`);
      lines.push(`Complaint: ${complaint.id} — ${complaint.title}`);
      lines.push('Concerns:');
      chosen.forEach(c => { lines.push(`- ${c.summary}`); if (c.details) lines.push(`  ${c.details}`); });
      const responses = chosen.flatMap(c => c.responses||[]);
      if (responses.length) { lines.push('Responses:'); responses.forEach(r => lines.push(`- ${r.date||''} ${r.decisionMaker||''}: ${r.text||''}`)); }
      return lines.join('\n');
    };
    qs('#consMail').addEventListener('click', () => {
      const to = (qs('#regEmail').value||'');
      const subject = encodeURIComponent(`Concerns regarding ${complaint.id}`);
      const body = encodeURIComponent(buildText());
      window.location.href = `mailto:${to}?subject=${subject}&body=${body}`;
    });
    qs('#consCopy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(buildText()); alert('Copied'); } catch { alert('Copy failed'); }
    });
  }

  function openShareSingleConcernModal(complaint, concern) {
    const root = qs('#modalRoot'); if (!root) return;
    const text = `Complaint ${complaint.id}: ${complaint.title}\nConcern: ${concern.summary}\n${concern.details||''}`;
    root.innerHTML = `
      <div class="modal-backdrop" id="shareOneModal">
        <div class="modal">
          <div class="modal-header"><div class="section-title">Share Concern</div><button class="btn secondary" id="shareOneClose">Close</button></div>
          <div class="modal-body"><div class="form"><div class="form-row"><label>Recipient Email<input id="oneEmail" placeholder="concerns@example.org" /></label></div><div class="form-row"><label>Summary<textarea id="oneSummary" rows="3">${text}</textarea></label></div></div></div>
          <div class="modal-footer form-actions"><button class="btn" id="oneMail">Open Email</button><button class="btn secondary" id="oneCopy">Copy</button></div>
        </div>
      </div>`;
    const close = () => { root.innerHTML = ''; };
    qs('#shareOneClose').addEventListener('click', close);
    qs('#shareOneModal').addEventListener('click', (e) => { if (e.target.id === 'shareOneModal') close(); });
    qs('#oneMail').addEventListener('click', () => {
      const to = qs('#oneEmail').value||'';
      const subject = encodeURIComponent(`Concern regarding ${complaint.id}`);
      const body = encodeURIComponent(qs('#oneSummary').value||'');
      window.location.href = `mailto:${to}?subject=${subject}&body=${body}`;
    });
    qs('#oneCopy').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(qs('#oneSummary').value||''); alert('Copied'); } catch { alert('Copy failed'); }
    });
  }

  // Inject demo-only items when logged out (not saved back to disk). Hidden after login.
  function injectDemoData() {
    try {
      // Accountability demo entries
      if (!Array.isArray(Data.accountability) || !Data.accountability.length) {
        Data.accountability = [
          { id: 'subj_demo1', subject: 'Sarah Matthews', role: 'Director', organisation: 'PSA', status: 'Open', allegations: 'Systemic denial of care; failure to act', harm: ['denial of care'], evidence: ['https://example.org/evidence-1'], dates: ['2025-07-02'], linkedComplaints: ['cmp_001'] },
          { id: 'subj_demo2', subject: 'Paul Philip', role: 'Chief Executive', organisation: 'GMC', status: 'Open', allegations: 'Negligence in oversight duties', harm: ['outing','harassment'], evidence: [], dates: [], linkedComplaints: ['cmp_001'] }
        ];
      }
      // Demo complaints (only if none loaded yet)
      if (!Array.isArray(Data.complaints) || !Data.complaints.length) {
        const base = [
          { id: 'cmp_001', title: 'Failure to respond to SAR', dateFiled: '2025-05-01', institution: 'Devon & Cornwall Police', contactPerson: 'PSD', complaintContent: 'No response received to SAR within statutory time.', linkedSAR: 'sar_001', concerns: [{ id:'conc_001', summary:'No monthly update', details:'Breach of agreed monthly contact', decisionMaker:'PSD', responseDate:'', evidence:['https://example.org/ref-1'], response:'', notes:[], attachments:[], responses:[] }], status: 'Filed', escalationPath: ['Filed'], isPasswordProtected: false, passwordHint:'', institutionAddress:'', institutionEmail:'', expectedResponseFrequency:'Monthly', lastResponseDate:'', agreedTerms:'Monthly update required', breachFlag:false, attachments:[], history: [] },
          { id: 'cmp_002', title: 'Complaint obstruction', dateFiled: '2025-06-10', institution: 'GMC', contactPerson: '', complaintContent: 'Refused to accept further complaints.', linkedSAR: '', concerns: [], status: 'Refused', escalationPath: ['Filed','Refused'], isPasswordProtected: false, passwordHint:'', institutionAddress:'', institutionEmail:'', expectedResponseFrequency:'', lastResponseDate:'', agreedTerms:'Agreed to accept further complaints', breachFlag:true, attachments:[], history: [] }
        ];
        // If specific user AAAPPP, seed distinct set
        const user = (Data.session && Data.session.user && Data.session.user.username) ? Data.session.user.username : 'public';
        if (user === 'AAAPPP') {
          Data.complaints = [
            { id: 'cmp_A01', title: 'AAAPPP Test Police Case', type:'Police', dateFiled: '2025-07-01', institution: 'Met Police', contactPerson: '', complaintContent: 'Test complaint for AAAPPP.', linkedSAR: '', concerns: [], status: 'Filed', escalationPath:['Filed'], isPasswordProtected:false, passwordHint:'', institutionAddress:'', institutionEmail:'', expectedResponseFrequency:'Weekly', lastResponseDate:'', agreedTerms:'', breachFlag:false, attachments:[], history: [] }
          ];
          Data.sars = [{ id:'sar_A01', title:'AAAPPP SAR', institution:'Met Police', dateFiled:'2025-06-15', status:'Pending', summary:'AAAPPP SAR test' }];
        } else {
          Data.complaints = base;
        }
      }
      // Demo SARs
      if (!Array.isArray(Data.sars) || !Data.sars.length) {
        Data.sars = [{ id:'sar_001', title:'Subject Access Request', institution:'Devon & Cornwall Police', dateFiled:'2025-04-15', status:'Pending', summary:'SAR submitted, awaiting response.' }];
      }
      // Render without persisting session-bound demo to localStorage (leave Data.save untouched here)
      renderAccountability();
    } catch {}
  }

  function openConcernModal(complaint, existing) {
    const root = qs('#modalRoot');
    if (!root) return;
    const isEdit = !!existing;
    const id = isEdit ? existing.id : Data.nextConcernId(complaint);
    root.innerHTML = `
      <div class="modal-backdrop" id="concernModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">${isEdit ? 'Edit Concern' : 'Add Concern'}</div>
            <button class="btn secondary" id="concernCancel">Close</button>
          </div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row">
                <label>Summary<input id="concSummary" value="${isEdit ? (existing.summary||'').replace(/"/g,'&quot;') : ''}" required /></label>
                <label>Decision Maker<input id="concDecision" value="${isEdit ? (existing.decisionMaker||'').replace(/"/g,'&quot;') : ''}" /></label>
              </div>
              <div class="form-row">
                <label>Response Date<input id="concRespDate" type="date" value="${isEdit ? (existing.responseDate||'') : ''}" /></label>
              </div>
              <div class="form-row">
                <label>Details<textarea id="concDetails" rows="4">${isEdit ? (existing.details||'') : ''}</textarea></label>
              </div>
              <div class="form-row">
                <label>Evidence URLs (comma-separated)<input id="concUrls" placeholder="https://..." value="${isEdit ? (Array.isArray(existing.evidence)?existing.evidence.join(', '):'') : ''}" /></label>
                <label>Attach Files<input id="concFiles" type="file" multiple /></label>
              </div>
              <div class="form-row">
                <label>Initial Response<textarea id="concResponse" rows="3">${isEdit ? (existing.response||'') : ''}</textarea></label>
              </div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="concernSave">${isEdit ? 'Save Changes' : 'Save Concern'}</button>
            <button class="btn secondary" id="concernCancel2">Cancel</button>
          </div>
        </div>
      </div>
    `;
    const close = () => { root.innerHTML = ''; };
    qs('#concernCancel').addEventListener('click', close);
    qs('#concernCancel2').addEventListener('click', close);
    qs('#concernModal').addEventListener('click', (e) => { if (e.target.id === 'concernModal') close(); });
    qs('#concernSave').addEventListener('click', async () => {
      const summary = (qs('#concSummary').value || '').trim();
      if (!summary) { alert('Summary is required'); return; }
      const details = (qs('#concDetails').value || '').trim();
      const decisionMaker = (qs('#concDecision').value || '').trim();
      const responseDate = (qs('#concRespDate').value || '').trim();
      const response = (qs('#concResponse').value || '').trim();
      const urls = (qs('#concUrls').value || '').split(',').map(s => s.trim()).filter(Boolean);
      const filesInput = qs('#concFiles');
      complaint.concerns = complaint.concerns || [];
      const concern = isEdit ? existing : { id, attachments: [], notes: [], responses: [] };
      concern.summary = summary;
      concern.details = details;
      concern.decisionMaker = decisionMaker;
      concern.responseDate = responseDate;
      concern.response = response;
      concern.evidence = urls;
      if (!isEdit) complaint.concerns.push(concern);
      const files = filesInput && filesInput.files ? filesInput.files : [];
      if (files && files.length) {
        const saved = await Data.saveFilesForConcern(complaint.id, concern.id, files);
        concern.attachments = saved.map(s => s.key);
      }
      await appendHistory(complaint, isEdit ? `Concern updated: ${summary}` : `Concern added: ${summary}`);
      Data.upsertComplaint(complaint);
      close();
      showComplaintDetails(complaint);
    });
  }

  function openResponseModal(complaint, concern) {
    const root = qs('#modalRoot');
    if (!root) return;
    const responseId = `${concern.id}-r${Math.random().toString(36).slice(2,7)}`;
    root.innerHTML = `
      <div class="modal-backdrop" id="respModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">Add Response</div>
            <button class="btn secondary" id="respCancel">Close</button>
          </div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row">
                <label>Date<input id="respDate" type="date" value="${new Date().toISOString().slice(0,10)}" /></label>
                <label>Decision Maker<input id="respDecision" value="${(concern.decisionMaker||'').replace(/"/g,'&quot;')}" /></label>
              </div>
              <div class="form-row">
                <label>Response<textarea id="respText" rows="4"></textarea></label>
              </div>
              <div class="form-row">
                <label>URLs (comma-separated)<input id="respUrls" placeholder="https://..." /></label>
                <label>Attach Files<input id="respFiles" type="file" multiple /></label>
              </div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="respSave">Save Response</button>
            <button class="btn secondary" id="respCancel2">Cancel</button>
          </div>
        </div>
      </div>
    `;
    const close = () => { root.innerHTML = ''; };
    qs('#respCancel').addEventListener('click', close);
    qs('#respCancel2').addEventListener('click', close);
    qs('#respModal').addEventListener('click', (e) => { if (e.target.id === 'respModal') close(); });
    qs('#respSave').addEventListener('click', async () => {
      const date = (qs('#respDate').value || '').trim();
      const decisionMaker = (qs('#respDecision').value || '').trim();
      const text = (qs('#respText').value || '').trim();
      const urls = (qs('#respUrls').value || '').split(',').map(s => s.trim()).filter(Boolean);
      concern.responses = Array.isArray(concern.responses) ? concern.responses : [];
      const resp = { id: responseId, date, decisionMaker, text, urls, attachments: [] };
      const filesInput = qs('#respFiles');
      const files = filesInput && filesInput.files ? filesInput.files : [];
      if (files && files.length) {
        const saved = await Data.saveFilesForConcernResponse(complaint.id, concern.id, responseId, files);
        resp.attachments = saved.map(s => s.key);
      }
      concern.responses.push(resp);
      await appendHistory(complaint, `Response added to concern: ${concern.summary}`);
      Data.upsertComplaint(complaint);
      close();
      showComplaintDetails(complaint);
    });
  }

  function openNoteModal(complaint, concern) {
    const root = qs('#modalRoot');
    if (!root) return;
    root.innerHTML = `
      <div class="modal-backdrop" id="noteModal">
        <div class="modal">
          <div class="modal-header">
            <div class="section-title">Add Note</div>
            <button class="btn secondary" id="noteCancel">Close</button>
          </div>
          <div class="modal-body">
            <div class="form">
              <div class="form-row">
                <label>Note<textarea id="noteText" rows="3"></textarea></label>
              </div>
              <div class="form-row">
                <label>URLs (comma-separated)<input id="noteUrls" placeholder="https://..." /></label>
              </div>
            </div>
          </div>
          <div class="modal-footer form-actions">
            <button class="btn" id="noteSave">Save Note</button>
            <button class="btn secondary" id="noteCancel2">Cancel</button>
          </div>
        </div>
      </div>
    `;
    const close = () => { root.innerHTML = ''; };
    qs('#noteCancel').addEventListener('click', close);
    qs('#noteCancel2').addEventListener('click', close);
    qs('#noteModal').addEventListener('click', (e) => { if (e.target.id === 'noteModal') close(); });
    qs('#noteSave').addEventListener('click', async () => {
      const text = (qs('#noteText').value || '').trim();
      const urls = (qs('#noteUrls').value || '').split(',').map(s => s.trim()).filter(Boolean);
      concern.notes = Array.isArray(concern.notes) ? concern.notes : [];
      concern.notes.push({ text, urls, date: new Date().toISOString().slice(0,10) });
      await appendHistory(complaint, `Note added to concern: ${concern.summary}`);
      Data.upsertComplaint(complaint);
      close();
      showComplaintDetails(complaint);
    });
  }

  function renderDetailsPlaceholder() {
    const panel = qs('#panel-details');
    if (!panel.classList.contains('active')) return;
    const container = qs('#detailsContainer');
    if (!container) return;
    const has = container.getAttribute('data-has-complaint') === '1';
    if (has) return;
    container.innerHTML = `
      <div class="card">
        <div class="section-title">Complaint Details</div>
        <div>Please Select or Add a Complaint</div>
      </div>
    `;
  }

  async function main() {
    setupTabs();
    setupThemeToggle();
    await Data.init();
    applyCustomTheme();
    // After data init, auto-create PHSO cases for complaints whose status includes 'PHSO'
    try {
      for (const c of Data.complaints) {
        if ((c.status||'').match(/phso/i)) {
          await autoCreatePhsoCase(c);
        }
      }
    } catch {}
    bindGlobalActions();
    handleAddComplaint();
    setupSecureLogin();
    renderAll();
    // Ensure a modal root exists
    if (!qs('#modalRoot')) {
      const div = document.createElement('div');
      div.id = 'modalRoot';
      document.body.appendChild(div);
    }
    // Load demo data into UI when logged out
    if (!(Data.session && Data.session.user)) {
      injectDemoData();
    }
  }

  document.addEventListener("DOMContentLoaded", main);
})();


