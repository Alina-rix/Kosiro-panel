(() => {
  "use strict";

  const API = window.location.origin;
  const TOKEN_KEY = "kosiro_token";

  const FAMILIES = [
    { title: "Xray", ids: ["proto_vless", "proto_trojan", "proto_vmess"] },
    { title: "sing-box", ids: ["proto_hy2", "proto_tuic", "proto_anytls"] },
    { title: "", ids: ["proto_mtproto", "proto_awg"], last: true },
  ];

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  let state = { token: sessionStorage.getItem(TOKEN_KEY) || "", protocols: [], users: [], offline: false };

  function toast(msg) {
    const el = $("#toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    setTimeout(() => el.classList.add("hidden"), 3200);
  }

  function setOffline(on) {
    state.offline = on;
    $("#conn-banner")?.classList.toggle("hidden", !on);
  }

  async function api(path, opts = {}) {
    const headers = { Accept: "application/json", ...(opts.headers || {}) };
    if (state.token && !opts.noAuth) headers.Authorization = "Bearer " + state.token;
    if (opts.body && typeof opts.body === "object") {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    let r;
    try {
      r = await fetch(API + path, { ...opts, headers });
    } catch {
      setOffline(true);
      throw new Error("Нет связи с сервером");
    }
    setOffline(false);
    if (r.status === 401) {
      logout(true);
      throw new Error("Сессия истекла — войдите снова");
    }
    const text = await r.text();
    let data = {};
    if (text) {
      try { data = JSON.parse(text); } catch { data = { raw: text }; }
    }
    if (!r.ok) throw new Error(data.error || data.message || `HTTP ${r.status}`);
    return data;
  }

  function logout(force) {
    if (!force && state.offline) return;
    state.token = "";
    sessionStorage.removeItem(TOKEN_KEY);
    $("#view-app").classList.add("hidden");
    $("#view-login").classList.remove("hidden");
    setOffline(false);
  }

  async function login() {
    const key = $("#login-key").value.trim();
    const errEl = $("#login-error");
    errEl.classList.add("hidden");
    if (!key) {
      errEl.textContent = "Введите admin key";
      errEl.classList.remove("hidden");
      return;
    }
    try {
      const data = await api("/v1/auth/token", { method: "POST", body: { admin_token: key }, noAuth: true });
      state.token = data.token;
      sessionStorage.setItem(TOKEN_KEY, state.token);
      $("#view-login").classList.add("hidden");
      $("#view-app").classList.remove("hidden");
      await boot();
    } catch (e) {
      errEl.textContent = e.message || "Ошибка входа";
      errEl.classList.remove("hidden");
    }
  }

  function showPage(name) {
    $$(".page").forEach((p) => p.classList.add("hidden"));
    $$(".nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.page === name));
    $("#page-" + name)?.classList.remove("hidden");
    if (name === "dashboard") loadDashboard();
    if (name === "users") loadUsers();
    if (name === "protocols") loadProtocols();
    if (name === "settings") loadSettings();
  }

  function fmtBytes(n) {
    if (n == null) return "—";
    const u = ["B", "KB", "MB", "GB", "TB"];
    let i = 0;
    let v = Number(n);
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return v.toFixed(i ? 1 : 0) + " " + u[i];
  }

  function fmtBps(n) {
    return n == null ? "—" : fmtBytes(n) + "/s";
  }

  function metricCard(label, value, pct, color) {
    const p = Math.min(100, Math.max(0, pct || 0));
    return `<div class="metric"><div class="label">${label}</div><div class="value">${value}</div>
      <div class="bar"><span style="width:${p}%;background:${color || "var(--accent)"}"></span></div></div>`;
  }

  async function loadDashboard() {
    try {
      const m = await api("/v1/system/metrics");
      $("#metrics-grid").innerHTML = [
        metricCard("CPU", (m.cpu_percent || 0).toFixed(1) + "%", m.cpu_percent, "var(--accent)"),
        metricCard("RAM", (m.ram_percent || 0).toFixed(1) + "%", m.ram_percent, "var(--warn)"),
        metricCard("Сеть ↓", fmtBps(m.net_down_bps), Math.min(100, (m.net_down_bps || 0) / 1e6), "var(--ok)"),
        metricCard("Диск", (m.disk_percent || 0).toFixed(1) + "%", m.disk_percent, "#b0a4ff"),
      ].join("");
      drawChart();
    } catch (e) { toast(e.message); }
  }

  async function drawChart() {
    const canvas = $("#chart-cpu");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const w = canvas.parentElement.clientWidth - 32;
    canvas.width = w;
    canvas.height = 120;
    let pts = [];
    try { pts = (await api("/v1/system/metrics/history?range=day")).points || []; } catch { /* */ }
    ctx.clearRect(0, 0, w, 120);
    if (!pts.length) {
      ctx.fillStyle = "#9a94a8";
      ctx.fillText("Нет истории (подождите минуту)", 12, 60);
      return;
    }
    const max = Math.max(...pts.map((p) => p.cpu_percent || 0), 1);
    ctx.strokeStyle = "#d0a6cc";
    ctx.lineWidth = 2;
    ctx.beginPath();
    pts.forEach((p, i) => {
      const x = (i / (pts.length - 1 || 1)) * (w - 24) + 12;
      const y = 110 - ((p.cpu_percent || 0) / max) * 90;
      i === 0 ? ctx.moveTo(x, y) : ctx.lineTo(x, y);
    });
    ctx.stroke();
  }

  async function loadUsers() {
    try {
      state.users = (await api("/v1/users")).users || [];
      const list = $("#users-list");
      if (!state.users.length) {
        list.innerHTML = '<p class="muted">Пока никого — создайте пользователя.</p>';
        return;
      }
      list.innerHTML = state.users.map((u) => {
        const subUrl = API + "/sub/" + u.subscription_token;
        return `<div class="user-row"><div>
          <div class="name">${esc(u.name)}</div>
          <div class="meta">UUID: ${esc(u.uuid)} · ${fmtBytes(u.traffic_used_bytes)} / ${fmtBytes(u.traffic_limit_bytes)}</div>
          <div class="meta"><code>${esc(subUrl)}</code></div></div>
          <div class="user-actions">
            <button class="btn small" data-copy="${esc(subUrl)}">Sub URL</button>
            <button class="btn small" data-user-sub="${esc(u.id)}">Ссылки</button>
            <button class="btn small" data-del-user="${esc(u.id)}">Удалить</button>
          </div></div>`;
      }).join("");
      list.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => {
        navigator.clipboard.writeText(b.dataset.copy);
        toast("Скопировано");
      }));
      list.querySelectorAll("[data-del-user]").forEach((b) => b.addEventListener("click", () => deleteUser(b.dataset.delUser)));
      list.querySelectorAll("[data-user-sub]").forEach((b) => b.addEventListener("click", () => showUserSub(b.dataset.userSub)));
    } catch (e) { toast(e.message); }
  }

  async function showUserSub(id) {
    const data = await api("/v1/users/" + id + "/subscription");
    openModal("Подписка", `<p><code>${esc(data.subscription_url)}</code></p><textarea readonly rows="8">${esc((data.uris || []).join("\n"))}</textarea>`, false);
    $("#modal-ok").onclick = closeModal;
  }

  async function deleteUser(id) {
    if (!confirm("Удалить?")) return;
    await api("/v1/users/" + id, { method: "DELETE" });
    toast("Удалён");
    loadUsers();
  }

  async function addUser() {
    const installed = state.protocols.filter((p) => p.installed && p.enabled).map((p) => p.id);
    openModal("Новый пользователь", `
      <label>Имя</label><input id="nu-name" placeholder="client-1" />
      <label>Лимит GB (0 = без лимита)</label><input id="nu-traffic" type="number" value="100" min="0" />`, false);
    $("#modal-ok").onclick = async () => {
      const name = $("#nu-name").value.trim();
      if (!name) return toast("Имя обязательно");
      const gb = parseFloat($("#nu-traffic").value) || 0;
      await api("/v1/users", {
        method: "POST",
        body: {
          name,
          traffic_limit_bytes: gb > 0 ? Math.round(gb * 1024 ** 3) : 0,
          billing_period: "month",
          exhaust_policy: "disconnect",
          enabled_protocol_ids: installed.length ? installed : state.protocols.filter((p) => p.installed).map((p) => p.id),
        },
      });
      closeModal();
      toast("Создан");
      loadUsers();
    };
  }

  function protoById(id) {
    return state.protocols.find((p) => p.id === id);
  }

  function renderProtoCard(p) {
    const isAwg = p.id === "proto_awg";
    const cls = ["proto-card", p.installed ? "installed" : "", p.enabled ? "enabled" : "", isAwg ? "soon" : ""].filter(Boolean).join(" ");
    const port = p.config?.port ?? "—";
    return `<div class="${cls}">
      <h4>${esc(p.display_name || p.type)} <span class="muted">:${port}</span></h4>
      <div class="proto-badges">
        <span class="badge ${p.installed ? "on" : ""}">${p.installed ? "готов" : "не установлен"}</span>
        <span class="badge ${p.enabled ? "on" : ""}">${p.enabled ? "вкл" : "выкл"}</span>
        ${isAwg ? '<span class="badge soon">Скоро</span>' : ""}
      </div>
      <div class="proto-actions">
        ${!isAwg && !p.installed ? `<button class="btn small primary" data-install="${esc(p.id)}">Установить</button>` : ""}
        ${!isAwg ? `<button class="btn small" data-toggle="${esc(p.id)}">${p.enabled ? "Выключить" : "Включить"}</button>` : ""}
        ${!isAwg ? `<button class="btn small" data-edit="${esc(p.id)}">Настроить</button>` : ""}
      </div></div>`;
  }

  async function loadProtocols() {
    try {
      state.protocols = (await api("/v1/protocols")).protocols || [];
      const mount = $("#protocols-mount");
      mount.innerHTML = FAMILIES.map((fam) => {
        const cards = fam.ids.map((id) => protoById(id)).filter(Boolean).map(renderProtoCard).join("");
        const title = fam.title ? `<h3 class="proto-family-title">${esc(fam.title)}</h3>` : "";
        return `<section class="proto-family${fam.last ? " last" : ""}">${title}<div class="proto-row">${cards}</div></section>`;
      }).join("");
      mount.querySelectorAll("[data-install]").forEach((b) => b.addEventListener("click", () => installProto(b.dataset.install)));
      mount.querySelectorAll("[data-toggle]").forEach((b) => b.addEventListener("click", () => toggleProto(b.dataset.toggle)));
      mount.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => editProto(b.dataset.edit)));
    } catch (e) { toast(e.message); }
  }

  async function installProto(id) {
    await api("/v1/protocols/" + id + "/install", { method: "POST" });
    toast("Установлен → «Применить»");
    loadProtocols();
  }

  async function toggleProto(id) {
    const p = protoById(id);
    if (!p) return;
    await api("/v1/protocols/" + id, { method: "PUT", body: { ...p, enabled: !p.enabled } });
    toast(p.enabled ? "Выключен" : "Включён");
    loadProtocols();
  }

  function field(label, id, value, type = "text", extra = "") {
    return `<label>${label}</label><input id="${id}" type="${type}" value="${esc(String(value ?? ""))}" ${extra} />`;
  }

  function selectField(label, id, value, options) {
    const opts = options.map(([v, t]) => `<option value="${esc(v)}"${v === value ? " selected" : ""}>${esc(t)}</option>`).join("");
    return `<label>${label}</label><select id="${id}">${opts}</select>`;
  }

  function segField(label, name, value, options) {
    const btns = options.map(([v, t]) =>
      `<button type="button" class="seg-btn${v === value ? " active" : ""}" data-seg="${name}" data-val="${esc(v)}">${esc(t)}</button>`
    ).join("");
    return `<label>${label}</label><div class="seg-group" id="seg-${name}">${btns}</div><input type="hidden" id="cfg-${name}" value="${esc(value)}" />`;
  }

  function bindSegGroups() {
    $$("[data-seg]").forEach((btn) => {
      btn.onclick = () => {
        const name = btn.dataset.seg;
        $$(`[data-seg="${name}"]`).forEach((b) => b.classList.toggle("active", b === btn));
        $(`#cfg-${name}`).value = btn.dataset.val;
        if (name === "security" || name === "transport") updateVlessSections();
      };
    });
  }

  function updateVlessSections() {
    const transport = $("#cfg-transport")?.value || "tcp";
    const security = $("#cfg-security")?.value || "none";
    $("#sec-reality")?.classList.toggle("hidden", security !== "reality");
    $("#sec-xhttp")?.classList.toggle("hidden", transport !== "xhttp");
    $("#sec-ws")?.classList.toggle("hidden", transport !== "ws");
    $("#sec-grpc")?.classList.toggle("hidden", transport !== "grpc");
    $("#sec-flow")?.classList.toggle("hidden", transport !== "tcp" || security === "none");
  }

  function vlessForm(cfg) {
    cfg = cfg || {};
    return `<div class="form-grid">
      ${field("Порт", "cfg-port", cfg.port ?? 443, "number")}
      ${field("Название в приложении", "cfg-remark", cfg.remark ?? "Kosiro-VLESS")}
      ${selectField("Транспорт", "cfg-transport", cfg.transport ?? "tcp", [
        ["tcp", "TCP"], ["xhttp", "XHTTP"], ["ws", "WebSocket"], ["grpc", "gRPC"],
      ])}
      ${segField("Безопасность", "security", cfg.security ?? "reality", [
        ["none", "None"], ["tls", "TLS"], ["reality", "REALITY"],
      ])}
      <div id="sec-flow" class="form-section">
        ${selectField("Flow (Vision)", "cfg-flow", cfg.flow ?? "xtls-rprx-vision", [
          ["xtls-rprx-vision", "XTLS Vision"], ["", "Без flow"],
        ])}
        <label><input type="checkbox" id="cfg-mux" ${cfg.mux ? "checked" : ""} /> Mux</label>
      </div>
      <div id="sec-reality" class="form-section">
        <h4>REALITY</h4>
        ${field("SNI", "cfg-sni", cfg.sni ?? "www.cloudflare.com")}
        ${field("Dest", "cfg-dest", cfg.dest ?? "www.cloudflare.com:443")}
        ${field("Public key", "cfg-public_key", cfg.public_key ?? "", "text", "readonly")}
        ${field("Short ID", "cfg-short_id", cfg.short_id ?? "")}
        ${selectField("Fingerprint", "cfg-fingerprint", cfg.fingerprint ?? "chrome", [
          ["chrome", "chrome"], ["firefox", "firefox"], ["safari", "safari"], ["ios", "ios"], ["random", "random"],
        ])}
      </div>
      <div id="sec-xhttp" class="form-section hidden">
        <h4>XHTTP</h4>
        ${field("Path", "cfg-xhttp_path", cfg.xhttp_path ?? "/")}
        ${selectField("Mode", "cfg-xhttp_mode", cfg.xhttp_mode ?? "auto", [
          ["auto", "auto"], ["packet-up", "packet-up"], ["stream-up", "stream-up"],
        ])}
        ${field("Host", "cfg-xhttp_host", cfg.xhttp_host ?? "")}
      </div>
      <div id="sec-ws" class="form-section hidden">
        <h4>WebSocket</h4>
        ${field("Path", "cfg-ws_path", cfg.ws_path ?? "/")}
        ${field("Host", "cfg-ws_host", cfg.ws_host ?? "")}
      </div>
      <div id="sec-grpc" class="form-section hidden">
        <h4>gRPC</h4>
        ${field("Service name", "cfg-grpc_service_name", cfg.grpc_service_name ?? "")}
      </div>
    </div>`;
  }

  function readVlessForm(base) {
    const cfg = { ...(base || {}) };
    cfg.port = parseInt($("#cfg-port").value, 10) || 443;
    cfg.remark = $("#cfg-remark").value.trim();
    cfg.transport = $("#cfg-transport").value;
    cfg.security = $("#cfg-security").value;
    cfg.flow = $("#cfg-flow").value;
    cfg.mux = $("#cfg-mux").checked;
    cfg.sni = $("#cfg-sni")?.value.trim() ?? cfg.sni;
    cfg.dest = $("#cfg-dest")?.value.trim() ?? cfg.dest;
    cfg.short_id = $("#cfg-short_id")?.value.trim() ?? cfg.short_id;
    cfg.fingerprint = $("#cfg-fingerprint")?.value ?? cfg.fingerprint;
    cfg.xhttp_path = $("#cfg-xhttp_path")?.value ?? cfg.xhttp_path;
    cfg.xhttp_mode = $("#cfg-xhttp_mode")?.value ?? cfg.xhttp_mode;
    cfg.xhttp_host = $("#cfg-xhttp_host")?.value.trim() ?? cfg.xhttp_host;
    cfg.ws_path = $("#cfg-ws_path")?.value ?? cfg.ws_path;
    cfg.ws_host = $("#cfg-ws_host")?.value.trim() ?? cfg.ws_host;
    cfg.grpc_service_name = $("#cfg-grpc_service_name")?.value.trim() ?? cfg.grpc_service_name;
    if (cfg.public_key) cfg.public_key = base.public_key;
    if (base.private_key) cfg.private_key = base.private_key;
    return cfg;
  }

  function trojanForm(cfg) {
    return `<div class="form-grid">
      ${field("Порт", "cfg-port", cfg.port ?? 8444, "number")}
      ${field("Название в приложении", "cfg-remark", cfg.remark ?? "Kosiro-Trojan")}
      ${selectField("Security", "cfg-security", cfg.security ?? "tls", [["none", "None"], ["tls", "TLS"]])}
      ${field("SNI", "cfg-sni", cfg.sni ?? "")}
    </div>`;
  }

  function vmessForm(cfg) {
    return `<div class="form-grid">
      ${field("Порт", "cfg-port", cfg.port ?? 10086, "number")}
      ${field("Название в приложении", "cfg-remark", cfg.remark ?? "Kosiro-VMess")}
      ${selectField("Transport", "cfg-network", cfg.network ?? "tcp", [["tcp", "TCP"], ["ws", "WS"], ["grpc", "gRPC"]])}
      ${selectField("Security", "cfg-security", cfg.security ?? "none", [["none", "None"], ["tls", "TLS"]])}
    </div>`;
  }

  function singboxForm(cfg, defaults) {
    return `<div class="form-grid">
      ${field("Порт", "cfg-port", cfg.port ?? defaults.port, "number")}
      ${field("Название в приложении", "cfg-remark", cfg.remark ?? defaults.remark)}
      ${field("SNI / Server name", "cfg-sni", cfg.sni ?? "")}
      ${defaults.cc ? selectField("Congestion", "cfg-congestion_control", cfg.congestion_control ?? "bbr", [["bbr", "BBR"], ["cubic", "Cubic"], ["new_reno", "New Reno"]]) : ""}
    </div>`;
  }

  function mtprotoForm(cfg) {
    return `<div class="form-grid">
      ${field("Порт", "cfg-port", cfg.port ?? 8446, "number")}
      ${field("Secret (пусто = автоген)", "cfg-secret", cfg.secret ?? "")}
      ${field("Спонсорский канал (TAG)", "cfg-sponsor_channel", cfg.sponsor_channel ?? "", "text", 'placeholder="@channel"')}
      <label><input type="checkbox" id="cfg-public_proxy" ${cfg.public_proxy ? "checked" : ""} /> Публичный прокси</label>
    </div>`;
  }

  function readSimpleForm(base, keys) {
    const cfg = { ...(base || {}) };
    keys.forEach((k) => {
      const el = $(`#cfg-${k.replace(/_/g, "-")}`) || $(`#cfg-${k}`);
      if (!el) return;
      if (el.type === "checkbox") cfg[k] = el.checked;
      else if (el.type === "number") cfg[k] = parseInt(el.value, 10) || cfg[k];
      else cfg[k] = el.value.trim();
    });
    return cfg;
  }

  function editProto(id) {
    const p = protoById(id);
    if (!p) return;
    const c = p.config || {};
    let html = "";
    if (id === "proto_vless") html = vlessForm(c);
    else if (id === "proto_trojan") html = trojanForm(c);
    else if (id === "proto_vmess") html = vmessForm(c);
    else if (id === "proto_hy2") html = singboxForm(c, { port: 8445, remark: "Kosiro-Hy2" });
    else if (id === "proto_tuic") html = singboxForm(c, { port: 8447, remark: "Kosiro-TUIC", cc: true });
    else if (id === "proto_anytls") html = singboxForm(c, { port: 8448, remark: "Kosiro-AnyTLS" });
    else if (id === "proto_mtproto") html = mtprotoForm(c);
    else return toast("Редактор для этого протокола позже");

    openModal(p.display_name || p.type, html, id === "proto_vless");
    if (id === "proto_vless") {
      bindSegGroups();
      $("#cfg-transport").onchange = updateVlessSections;
      updateVlessSections();
    }
    $("#modal-ok").onclick = async () => {
      let cfg = c;
      if (id === "proto_vless") cfg = readVlessForm(c);
      else if (id === "proto_trojan") cfg = readSimpleForm(c, ["port", "remark", "security", "sni"]);
      else if (id === "proto_vmess") cfg = readSimpleForm(c, ["port", "remark", "network", "security"]);
      else if (id === "proto_hy2" || id === "proto_anytls") cfg = readSimpleForm(c, ["port", "remark", "sni"]);
      else if (id === "proto_tuic") cfg = readSimpleForm(c, ["port", "remark", "sni", "congestion_control"]);
      else if (id === "proto_mtproto") cfg = readSimpleForm(c, ["port", "secret", "sponsor_channel", "public_proxy"]);
      try {
        await api("/v1/protocols/" + id, { method: "PUT", body: { ...p, config: cfg } });
        closeModal();
        toast("Сохранено → «Применить»");
        loadProtocols();
      } catch (e) { toast(e.message); }
    };
  }

  async function applyProtocols() {
    await api("/v1/protocols/apply", { method: "POST" });
    toast("Применено (Xray перезапущен)");
  }

  async function loadSettings() {
    const sub = await api("/v1/settings/subscription");
    $("#set-base-url").value = sub.base_public_url || API;
    $("#set-sub-path").value = sub.subscription_path || "/sub/";
    const xr = await api("/v1/settings/xray");
    $("#set-xray-log").value = xr.log_level || "warning";
  }

  async function saveSettings() {
    await api("/v1/settings/subscription", {
      method: "PUT",
      body: {
        base_public_url: $("#set-base-url").value.trim() || API,
        subscription_path: $("#set-sub-path").value.trim() || "/sub/",
        subscription_kind: "v2ray_base64",
      },
    });
    toast("Сохранено");
  }

  async function saveXraySettings() {
    await api("/v1/settings/xray", {
      method: "PUT",
      body: { log_level: $("#set-xray-log").value, api_listen: "0.0.0.0:10085" },
    });
    toast("Xray OK");
  }

  function openModal(title, html, wide) {
    $("#modal-title").textContent = title;
    $("#modal-body").innerHTML = html;
    $("#modal .modal-box").classList.toggle("wide", !!wide);
    $("#modal").classList.remove("hidden");
    $("#modal-cancel").onclick = closeModal;
  }

  function closeModal() {
    $("#modal").classList.add("hidden");
    $("#modal-body").innerHTML = "";
  }

  function esc(s) {
    return String(s ?? "").replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/"/g, "&quot;");
  }

  async function pingHealth() {
    try {
      const r = await fetch(API + "/health");
      return r.ok;
    } catch { return false; }
  }

  async function tryRestoreSession() {
    if (!state.token) {
      $("#view-login").classList.remove("hidden");
      return;
    }
    $("#view-login").classList.add("hidden");
    $("#view-app").classList.remove("hidden");
    if (await pingHealth()) {
      setOffline(false);
      await boot();
    } else {
      setOffline(true);
      showPage("dashboard");
    }
  }

  async function boot() {
    showPage("dashboard");
    try { state.protocols = (await api("/v1/protocols")).protocols || []; } catch { /* */ }
  }

  function init() {
    $("#btn-login").addEventListener("click", login);
    $("#login-key").addEventListener("keydown", (e) => e.key === "Enter" && login());
    $("#btn-logout").addEventListener("click", () => logout(true));
    $("#btn-reconnect").addEventListener("click", tryRestoreSession);
    $$(".nav-btn").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
    $("#btn-add-user").addEventListener("click", addUser);
    $("#btn-apply-protocols").addEventListener("click", () => applyProtocols().catch((e) => toast(e.message)));
    $("#btn-save-settings").addEventListener("click", () => saveSettings().catch((e) => toast(e.message)));
    $("#btn-save-xray").addEventListener("click", () => saveXraySettings().catch((e) => toast(e.message)));
    tryRestoreSession();
  }

  init();
})();
