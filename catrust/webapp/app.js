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
      query: "",
      openRow: null,   // store id whose detail row is open
      logLines: [],
      busy: false,
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
        (s.alerts || []).some(a => (a.subject + a.serial + a.spki_hash).toLowerCase().includes(q)));
    },
    affectedCount() { return this.stores.filter(s => (s.alerts || []).length > 0).length; },
    alertCount() { return this.stores.reduce((n, s) => n + (s.alerts || []).length, 0); },
  },
  methods: {
    log(msg, cls = "") {
      const time = new Date().toLocaleTimeString();
      this.logLines.push({ time, msg, cls });
      this.$nextTick(() => {
        const el = document.getElementById("log");
        if (el) el.scrollTop = el.scrollHeight;
      });
    },
    async audit() {
      this.busy = true;
      this.log("🔍 auditing all CA stores…");
      try {
        const r = await fetch("/api/audit", { method: "POST" });
        const data = await r.json();
        this.stores = data.stores || [];
        this.blocklist = data.blocklist || [];
        this.log(`audit: ${this.stores.length} stores, ${this.affectedCount} affected, ` +
                 `${this.blocklist.length} blocklist entries`, this.affectedCount ? "err" : "ok");
      } catch (e) { this.log("audit failed: " + e, "err"); }
      this.busy = false;
    },
    async updateCrl() {
      this.busy = true;
      this.log("📥 updating CRL (application-level blocklist)…");
      try {
        const r = await fetch("/api/crl/update", {
          method: "POST", headers: { "Content-Type": "application/json" }, body: "{}",
        });
        const data = await r.json();
        this.blocklist = data.entries || [];
        this.log(`CRL update: ${this.blocklist.length} untrusted entries`, "warn");
        await this.audit();
      } catch (e) { this.log("CRL update failed: " + e, "err"); }
      this.busy = false;
    },
    jumpToAffected() {
      const first = this.stores.find(s => (s.alerts || []).length > 0);
      if (first) {
        this.openRow = first.id;
        this.log(`🚨 jumped to first affected store: ${first.name} (${first.alerts.length} alerts)`, "err");
        this.$nextTick(() => document.querySelector("tr.open")?.scrollIntoView({ block: "center" }));
      } else this.log("no affected stores — nothing to jump to", "ok");
    },
    async remediate(storeId, mode) {
      this.busy = true;
      this.log(`${mode === "root" ? "☢️ distrusting entire root" : "🔬 distrusting SPKI hash"} in ${storeId}…`, "warn");
      try {
        const r = await fetch("/api/remediate", {
          method: "POST", headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ store_id: storeId, mode }),
        });
        const res = await r.json();
        if (res.success) for (const a of res.actions || []) this.log(`${storeId}: ${a}`, "ok");
        else this.log(`${storeId}: FAILED — ${res.error}`, "err");
        await this.audit();
      } catch (e) { this.log("remediate failed: " + e, "err"); }
      this.busy = false;
    },
  },
  mounted() { this.audit(); },
}).mount("#app");
