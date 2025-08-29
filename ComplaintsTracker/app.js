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
    async init() {
      // Load from localStorage, fallback to bundled JSON
      const lsComplaints = localStorage.getItem(STORAGE_KEYS.complaints);
      const lsSars = localStorage.getItem(STORAGE_KEYS.sars);
      const lsPhso = localStorage.getItem(STORAGE_KEYS.phso);
      const lsLegal = localStorage.getItem(STORAGE_KEYS.legal);
      const lsAcc = localStorage.getItem(STORAGE_KEYS.accountability);
      const lsUsers = localStorage.getItem(STORAGE_KEYS.users);
      const lsSession = localStorage.getItem(STORAGE_KEYS.session);
      if (lsComplaints && lsSars) {
        try {
          this.complaints = JSON.parse(lsComplaints);
          this.sars = JSON.parse(lsSars);
          this.phsoCases = lsPhso ? JSON.parse(lsPhso) : [];
          this.legalCases = lsLegal ? JSON.parse(lsLegal) : [];
          this.accountability = lsAcc ? JSON.parse(lsAcc) : [];
          this.users = lsUsers ? JSON.parse(lsUsers) : [];
          this.session = lsSession ? JSON.parse(lsSession) : { user: null };
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
    async _loadFromFiles() {
      const [complaintsRes, sarsRes] = await Promise.all([
        fetch("data/complaints.json"),
        fetch("data/sars.json"),
      ]);
      this.complaints = await complaintsRes.json();
      this.sars = await sarsRes.json();
    },
    save() {
      localStorage.setItem(STORAGE_KEYS.complaints, JSON.stringify(this.complaints));
      localStorage.setItem(STORAGE_KEYS.sars, JSON.stringify(this.sars));
      localStorage.setItem(STORAGE_KEYS.phso, JSON.stringify(this.phsoCases));
      localStorage.setItem(STORAGE_KEYS.legal, JSON.stringify(this.legalCases));
      localStorage.setItem(STORAGE_KEYS.accountability, JSON.stringify(this.accountability));
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
  }

  function renderFilters() {
    const instSel = qs("#filterInstitution");
    const statusSel = qs("#filterStatus");
    const institutions = Array.from(new Set(Data.complaints.map(c => c.institution).filter(Boolean))).sort();
    const statuses = Array.from(new Set(Data.complaints.map(c => c.status).filter(Boolean))).sort();
    instSel.innerHTML = `<option value="">All Institutions</option>` + institutions.map(i => `<option>${i}</option>`).join("");
    statusSel.innerHTML = `<option value="">All Statuses</option>` + statuses.map(s => `<option>${s}</option>`).join("");
  }

  function computeMetrics() {
    const total = Data.complaints.length;
    const escalated = Data.complaints.filter(c => (c.status||"").toLowerCase().includes("escalated")).length;
    const unresolved = Data.complaints.filter(c => !/(resolved|closed)/i.test(c.status || "")).length;
    qs("#metricTotal").textContent = String(total);
    qs("#metricEscalated").textContent = String(escalated);
    qs("#metricUnresolved").textContent = String(unresolved);
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
    const results = qs("#searchResults");
    const apply = () => {
      const q = (input.value || "").toLowerCase();
      const inst = instSel.value;
      const stat = statusSel.value;
      const filtered = Data.complaints.filter(c => {
        const matchesQ = !q || JSON.stringify(c).toLowerCase().includes(q);
        const matchesI = !inst || c.institution === inst;
        const matchesS = !stat || c.status === stat;
        return matchesQ && matchesI && matchesS;
      });
      results.innerHTML = "";
      filtered.forEach(c => {
        const div = document.createElement("div");
        div.className = "list-item";
        div.innerHTML = `<div><strong>${c.title}</strong><div class="list-meta">${c.institution} • ${c.status}</div></div><div><button class="btn secondary" data-id="${c.id}">Open</button></div>`;
        results.appendChild(div);
      });
    };
    [input, instSel, statusSel].forEach(el => el.addEventListener("input", apply));
    qs("#clearFiltersBtn").addEventListener("click", () => { input.value = ""; instSel.value = ""; statusSel.value = ""; apply(); });
    apply();
    results.addEventListener("click", (e) => {
      const btn = e.target.closest("button[data-id]");
      if (!btn) return;
      const c = Data.getComplaint(btn.getAttribute("data-id"));
      if (c) showComplaintDetails(c);
    });
  }

  function populateLinkedSarSelect() {
    const sel = qs("#linkedSarSelect");
    sel.innerHTML = `<option value="">None</option>` + Data.sars.map(s => `<option value="${s.id}">${s.id} — ${s.title}</option>`).join("");
  }

  async function populateInstitutionSelect() {
    const sel = qs('#institutionSelect');
    const addr = qs('#institutionAddress');
    const mail = qs('#institutionEmail');
    const rows = await loadInstitutions();
    const dl = qs('#institutionList');
    if (dl) dl.innerHTML = rows.map(r => `<option value="${r.name}" data-address="${r.address||''}" data-email="${r.email||''}"></option>`).join('');
    sel.addEventListener('input', () => {
      const val = sel.value;
      const match = rows.find(r => r.name === val);
      if (match) { addr.value = match.address || ''; mail.value = match.email || ''; }
    });
    const addBtn = qs('#addInstitutionBtn');
    if (addBtn) addBtn.onclick = () => openAddInstitutionModal(sel);
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
    el.innerHTML = `
      <div class="grid">
        <div class="card">
          <div class="section-title">Overview</div>
          <div><strong>${complaint.title}</strong></div>
          <div class="list-meta">${complaint.institution} • ${fmtDate(complaint.dateFiled)} • ${complaint.status}</div>
          <div class="list-meta">${sarLabel}</div>
          <div style="margin-top:8px;">${complaint.complaintContent}</div>
          ${complaint.isPasswordProtected ? `<div class="chip protected" style="margin-top:8px;">Password Protected${complaint.passwordHint?` — Hint: ${complaint.passwordHint}`:""}</div>` : ""}
          <div class="chip" style="margin-top:8px;">Audit Trail: ${auditOk ? "Valid" : "Invalid"}</div>
          <div class="form-actions" style="margin-top:10px;">
            ${complaint.isPasswordProtected ? `<button class="btn" id="unlockBtn">Unlock</button>` : ""}
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
            ${(complaint.concerns||[]).map(cc => `
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

  function showLinkedSar(sarId) {
    const sar = Data.sars.find(s => s.id === sarId);
    // Switch to tab
    qsa(".tab").forEach(btn => btn.classList.toggle("active", btn.dataset.tab === "linked-sar"));
    qsa(".panel").forEach(p => p.classList.remove("active"));
    const panel = qs("#panel-linked-sar");
    panel.classList.add("active");
    if (!sar) { panel.innerHTML = `<div class="card">No SAR found: ${sarId}</div>`; return; }
    panel.innerHTML = `
      <div class="card">
        <div class="section-title">Linked SAR</div>
        <div><strong>${sar.title}</strong></div>
        <div class="list-meta">${sar.institution} • ${fmtDate(sar.dateFiled)} • ${sar.status}</div>
        <div style="margin-top:8px;">${sar.summary || ""}</div>
      </div>
    `;
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
  }

  function renderAll() {
    renderFilters();
    computeMetrics();
    renderComplaintsList();
    renderSearch();
    populateLinkedSarSelect();
    populateInstitutionSelect();
    renderLegalOverview();
    renderAccountability();
    renderCalendar();
    renderDetailsPlaceholder();
    renderResources();
  }

  function renderLegalOverview() {
    const panel = qs('#panel-legal');
    if (!panel.classList.contains('active')) return; // only render when visible
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
          renderAll();
          alert('Logged in as admin');
          return;
        }
        const user = Data.users.find(u => u.username === username && u.password === password);
        if (!user) { alert('Invalid credentials'); return; }
        Data.session.user = { username, role: 'user' };
        Data.save();
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
    if (!panel.classList.contains('active')) return;
    const container = qs('#accountabilityContainer');
    const list = Data.accountability || [];
    const rows = list.map(s => `
      <div class="list-item">
        <div>
          <div><strong>${s.subject}</strong> — ${s.role||''} @ ${s.organisation||''}</div>
          <div class="list-meta">Status: ${s.status||'Open'} • Harm: ${(s.harm||[]).join(', ')}</div>
        </div>
        <div class="list-actions">
          <button class="btn secondary" data-action="open" data-id="${s.id}">Open</button>
        </div>
      </div>
    `).join('') || '<div class="list-item"><div>No accountability subjects</div></div>';
    container.innerHTML = `
      <div class="list-header">
        <div>Subjects</div>
        <div class="list-actions">
          <button class="btn secondary" id="accAddBtn">+ Add Entry</button>
          <button class="btn secondary" id="accExportBtn">Master Report Export</button>
        </div>
      </div>
      <div class="list">${rows}</div>
    `;
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


