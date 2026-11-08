// RootCanal dashboard — Vue 3 (vendored, no build step). Person B owns this file.
// Layout: [box1] search + Audit CA stores / Update CRL / Jump to Affected
//         [box2] stores table, click row -> roots list + CRL alert + distrust buttons
//         [box3] live log at the bottom.
// API contract (catrust/web.py):
//   POST /api/audit      -> { stores: [{ id, name, icon, status, total_roots,
//                          roots: [RootInfo], alerts: [BlocklistEntry] }], blocklist: [...] }
//   POST /api/crl/update -> body {crl_pem?|url?} -> { entries: [BlocklistEntry] }
//   POST /api/remediate  -> body { store_id, mode: "spki"|"root" } -> { success, actions, error }
const { createApp } = Vue;

createApp({
  data() {
    return {
      stores: [],
      blocklist: [],
      scenarioName: "",
      query: "",
      openRow: null,   // store id whose detail row is open
      logLines: [],
      busy: false,
      theme: document.documentElement.dataset.theme || "dark",
      sortMode: "none",        // "none" | "urgent" | "recent"
      alertPick: {},           // storeId -> selected alert index (dropdown of first 5)
      modalStoreId: null,      // store whose alert popup ("tab") is open
    };
  },
  computed: {
    filteredStores() {
      const q = this.query.trim().toLowerCase();
      if (!q) return this.stores;
      return this.stores.filter(s =>
        s.name.toLowerCase().includes(q) ||
        s.id.toLowerCase().includes(q) ||
        (s.roots || []).some(r => r.subject.toLowerCase().includes(q) || (r.flags || []).some(f => f.includes(q))) ||
        (s.alerts || []).some(a => (a.subject + " " + a.serial + " " + a.spki_hash + " " + a.reason).toLowerCase().includes(q)) ||
        (s.findings || []).some(f => (f.kind + " " + f.detail).toLowerCase().includes(q)));
    },
    affectedCount() { return this.stores.filter(s => this.statusOf(s) === "alert").length; },
    alertCount() { return this.stores.reduce((n, s) => n + (s.alerts || []).length + (s.findings || []).length, 0); },
    blocklistSources() {
      const srcs = [...new Set(this.blocklist.map(e => e.source || "CRL"))];
      return srcs.join(", ");
    },
    sortedStores() {
      const arr = [...this.filteredStores];
      if (this.sortMode === "urgent") {
        arr.sort((a, b) => this.urgency(b) - this.urgency(a) || a.name.localeCompare(b.name));
      } else if (this.sortMode === "recent") {
        arr.sort((a, b) => this.latestAlert(b).localeCompare(this.latestAlert(a)) ||
                          a.name.localeCompare(b.name));
      }
      return arr;
    },
    // store behind the alert popup (kept by id so it stays fresh after re-audit)
    modalStore() {
      return this.stores.find(s => s.id === this.modalStoreId) || null;
    },
  },
  methods: {
    toggleTheme() {
      this.theme = this.theme === "dark" ? "light" : "dark";
      document.documentElement.dataset.theme = this.theme;
      try { localStorage.setItem("rootcanal-theme", this.theme); } catch (e) { /* private mode */ }
      this.log(`🎨 switched to ${this.theme} mode`);
    },
    statusOf(s) {
      if (s.status) return s.status;
      return ((s.alerts || []).length || (s.findings || []).length) ? "alert" : "ok";
    },
    // urgency score: revoked serials (actively abused certs) > known-bad roots >
    // distrusted SPKI keys > generic findings
    urgency(s) {
      let score = 0;
      for (const a of s.alerts || []) {
        if (a.serial) score += 20;
        if (a.spki_hash) score += 10;
      }
      score += (s.roots || []).filter(r => (r.flags || []).includes("known-bad")).length * 15;
      score += (s.findings || []).length * 5;
      return score;
    },
    latestAlert(s) {
      let m = "";
      for (const a of s.alerts || []) if (a.revoked_at && a.revoked_at > m) m = a.revoked_at;
      return m;
    },
    setSort(mode) {
      this.sortMode = this.sortMode === mode ? "none" : mode;
      this.log(this.sortMode === "none"
        ? "↕ sort reset (original order)"
        : `↕ sorted by ${this.sortMode === "urgent" ? "🔥 most urgent" : "🕒 most recent"}`, "");
    },
    selectedAlertIndex(s) {
      const n = Math.min(5, (s.alerts || []).length);
      const p = this.alertPick[s.id];
      return (p === undefined || p >= n) ? 0 : p;
    },
    log(msg, cls = "") {
      const time = new Date().toLocaleTimeString();
      this.logLines.push({ time, msg, cls });
      this.$nextTick(() => {
        const el = document.getElementById("log");
        if (el) el.scrollTop = el.scrollHeight;
      });
    },
    // POST helper: throws with the server's JSON error message when the API fails
    async post(url, body) {
      const r = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body || {}),
      });
      const data = await r.json().catch(() => ({}));
      if (!r.ok) throw new Error(data.error || `HTTP ${r.status}`);
      return data;
    },
    async audit() {
      this.busy = true;
      this.log("🔍 auditing all CA stores…");
      try {
        const data = await this.post("/api/audit");
        this.stores = data.stores || [];
        this.blocklist = data.blocklist || [];
        this.scenarioName = (data.scenario && data.scenario.name) || "";
        this.log(`audit: ${this.stores.length} stores, ${this.affectedCount} affected, ` +
                 `${this.blocklist.length} blocklist entries`, this.affectedCount ? "err" : "ok");
      } catch (e) { this.log("audit failed: " + e.message, "err"); }
      this.busy = false;
    },
    async updateCrl() {
      this.busy = true;
      this.log("📥 updating CRL (application-level blocklist)…");
      try {
        const data = await this.post("/api/crl/update");
        this.blocklist = data.entries || [];
        this.log(`CRL update: ${this.blocklist.length} untrusted entries`, "warn");
        await this.audit();
      } catch (e) { this.log("CRL update failed: " + e.message, "err"); }
      this.busy = false;
    },
    jumpToAffected() {
      const first = this.stores.find(s => this.statusOf(s) === "alert");
      if (first) this.openAlerts(first, "🚨 jumped to first affected store: ");
      else this.log("no affected stores — nothing to jump to", "ok");
    },
    // clicking the row's ALERT badge (or Jump to Affected) opens the row AND
    // pops up the "tab" with the first 5 alerts of that store
    openAlerts(s, prefix = "⚠ ") {
      this.openRow = s.id;
      this.modalStoreId = s.id;
      this.log(`${prefix}${s.name}: showing first 5 of ${(s.alerts || []).length} alert(s)`, "err");
      this.$nextTick(() =>
        document.querySelector("tr.open .alert-box")?.scrollIntoView({ block: "center" }));
    },
    async remediate(storeId, mode) {
      this.busy = true;
      this.log(`${mode === "root" ? "☢️ distrusting entire root" : "🔬 distrusting SPKI hash"} in ${storeId}…`, "warn");
      try {
        const res = await this.post("/api/remediate", { store_id: storeId, mode });
        if (res.success) for (const a of res.actions || []) this.log(`${storeId}: ${a}`, "ok");
        else this.log(`${storeId}: FAILED — ${res.error}`, "err");
        await this.audit();   // row flips to ok; keep the row open
      } catch (e) { this.log("remediate failed: " + e.message, "err"); }
      this.busy = false;
    },
  },
  mounted() { this.audit(); },
}).mount("#app");
