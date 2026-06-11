(() => {
  "use strict";

  const API = window.location.origin;
  const TOKEN_KEY = "kosiro_token";

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => [...document.querySelectorAll(sel)];

  let state = { token: sessionStorage.getItem(TOKEN_KEY) || "", protocols: [], users: [] };

  function toast(msg) {
    const el = $("#toast");
    el.textContent = msg;
    el.classList.remove("hidden");
    setTimeout(() => el.classList.add("hidden"), 3200);
  }

  async function api(path, opts = {}) {
    const headers = { Accept: "application/json", ...(opts.headers || {}) };
    if (state.token && !opts.noAuth) headers.Authorization = "Bearer " + state.token;
    if (opts.body && typeof opts.body === "object") {
      headers["Content-Type"] = "application/json";
      opts.body = JSON.stringify(opts.body);
    }
    const r = await fetch(API + path, { ...opts, headers });
    if (r.status === 401) {
      logout();
      throw new Error("Сессия истекла");
    }
    const text = await r.text();
    let data = {};
    if (text) {
      try { data = JSON.parse(text); } catch { data = { raw: text }; }
    }
    if (!r.ok) throw new Error(data.error || data.message || `HTTP ${r.status}`);
    return data;
  }

  function logout() {
    state.token = "";
    sessionStorage.removeItem(TOKEN_KEY);
    $("#view-app").classList.add("hidden");
    $("#view-login").classList.remove("hidden");
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
      const data = await api("/v1/auth/token", {
        method: "POST",
        body: { admin_token: key },
        noAuth: true,
      });
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
    const page = $("#page-" + name);
    if (page) page.classList.remove("hidden");
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
    if (n == null) return "—";
    return fmtBytes(n) + "/s";
  }

  function metricCard(label, value, pct, color) {
    const p = Math.min(100, Math.max(0, pct || 0));
    return `<div class="metric">
      <div class="label">${label}</div>
      <div class="value">${value}</div>
      <div class="bar"><span style="width:${p}%;background:${color || "var(--accent)"}"></span></div>
    </div>`;
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
      drawChart(m);
    } catch (e) {
      toast(e.message);
    }
  }

  async function drawChart() {
    const canvas = $("#chart-cpu");
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    const w = canvas.parentElement.clientWidth - 32;
    canvas.width = w;
    canvas.height = 120;
    let pts = [];
    try {
      const hist = await api("/v1/system/metrics/history?range=day");
      pts = hist.points || [];
    } catch { /* ignore */ }
    ctx.clearRect(0, 0, w, 120);
    if (!pts.length) {
      ctx.fillStyle = "#9a94a8";
      ctx.fillText("Нет истории (подождите минуту после старта)", 12, 60);
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
      const data = await api("/v1/users");
      state.users = data.users || [];
      const list = $("#users-list");
      if (!state.users.length) {
        list.innerHTML = '<p class="muted">Пока никого — создайте пользователя.</p>';
        return;
      }
      list.innerHTML = state.users.map((u) => {
        const subPath = "/sub/" + u.subscription_token;
        const subUrl = API + subPath;
        return `<div class="user-row">
          <div>
            <div class="name">${esc(u.name)}</div>
            <div class="meta">UUID: ${esc(u.uuid)} · трафик: ${fmtBytes(u.traffic_used_bytes)} / ${fmtBytes(u.traffic_limit_bytes)}</div>
            <div class="meta">Подписка: <code>${esc(subUrl)}</code></div>
          </div>
          <div class="user-actions">
            <button class="btn small" data-copy="${esc(subUrl)}">Копировать sub</button>
            <button class="btn small" data-user-sub="${esc(u.id)}">Ссылки</button>
            <button class="btn small" data-del-user="${esc(u.id)}">Удалить</button>
          </div>
        </div>`;
      }).join("");
      list.querySelectorAll("[data-copy]").forEach((btn) => {
        btn.addEventListener("click", () => {
          navigator.clipboard.writeText(btn.dataset.copy);
          toast("Скопировано");
        });
      });
      list.querySelectorAll("[data-del-user]").forEach((btn) => {
        btn.addEventListener("click", () => deleteUser(btn.dataset.delUser));
      });
      list.querySelectorAll("[data-user-sub]").forEach((btn) => {
        btn.addEventListener("click", () => showUserSub(btn.dataset.userSub));
      });
    } catch (e) {
      toast(e.message);
    }
  }

  async function showUserSub(id) {
    try {
      const data = await api("/v1/users/" + id + "/subscription");
      openModal("Подписка пользователя", `<p><strong>URL:</strong><br><code>${esc(data.subscription_url)}</code></p>
        <textarea readonly rows="8">${esc((data.uris || []).join("\n"))}</textarea>`);
      $("#modal-ok").onclick = closeModal;
    } catch (e) {
      toast(e.message);
    }
  }

  async function deleteUser(id) {
    if (!confirm("Удалить пользователя?")) return;
    try {
      await api("/v1/users/" + id, { method: "DELETE" });
      toast("Удалён");
      loadUsers();
    } catch (e) {
      toast(e.message);
    }
  }

  async function addUser() {
    const installed = state.protocols.filter((p) => p.installed && p.enabled).map((p) => p.id);
    openModal("Новый пользователь", `
      <label>Имя</label>
      <input id="nu-name" type="text" placeholder="client-1" />
      <label>Лимит трафика (GB, 0 = без лимита)</label>
      <input id="nu-traffic" type="number" value="100" min="0" />
    `);
    $("#modal-ok").onclick = async () => {
      const name = $("#nu-name").value.trim();
      if (!name) { toast("Имя обязательно"); return; }
      const gb = parseFloat($("#nu-traffic").value) || 0;
      try {
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
      } catch (e) {
        toast(e.message);
      }
    };
  }

  async function loadProtocols() {
    try {
      const data = await api("/v1/protocols");
      state.protocols = data.protocols || [];
      const grid = $("#protocols-grid");
      grid.innerHTML = state.protocols.map((p) => {
        const cls = ["proto-card", p.installed ? "installed" : "", p.enabled ? "enabled" : ""].filter(Boolean).join(" ");
        return `<div class="${cls}" data-id="${esc(p.id)}">
          <h4>${esc(p.display_name || p.type)}</h4>
          <div class="proto-badges">
            <span class="badge ${p.installed ? "on" : ""}">${p.installed ? "установлен" : "не установлен"}</span>
            <span class="badge ${p.enabled ? "on" : ""}">${p.enabled ? "включён" : "выкл"}</span>
            <span class="badge">${esc(p.type)}</span>
          </div>
          <div class="proto-actions">
            ${!p.installed ? `<button class="btn small primary" data-install="${esc(p.id)}">Установить</button>` : ""}
            <button class="btn small" data-toggle="${esc(p.id)}">${p.enabled ? "Выключить" : "Включить"}</button>
            <button class="btn small" data-edit="${esc(p.id)}">Настроить</button>
          </div>
        </div>`;
      }).join("");

      grid.querySelectorAll("[data-install]").forEach((b) => b.addEventListener("click", () => installProto(b.dataset.install)));
      grid.querySelectorAll("[data-toggle]").forEach((b) => b.addEventListener("click", () => toggleProto(b.dataset.toggle)));
      grid.querySelectorAll("[data-edit]").forEach((b) => b.addEventListener("click", () => editProto(b.dataset.edit)));
    } catch (e) {
      toast(e.message);
    }
  }

  async function installProto(id) {
    try {
      await api("/v1/protocols/" + id + "/install", { method: "POST" });
      toast("Установлен — не забудь «Применить»");
      loadProtocols();
    } catch (e) {
      toast(e.message);
    }
  }

  async function toggleProto(id) {
    const p = state.protocols.find((x) => x.id === id);
    if (!p) return;
    try {
      await api("/v1/protocols/" + id, {
        method: "PUT",
        body: { ...p, enabled: !p.enabled },
      });
      toast(p.enabled ? "Выключен" : "Включён");
      loadProtocols();
    } catch (e) {
      toast(e.message);
    }
  }

  async function editProto(id) {
    const p = state.protocols.find((x) => x.id === id);
    if (!p) return;
    const cfg = JSON.stringify(p.config || {}, null, 2);
    openModal("Настройка: " + (p.display_name || p.type), `
      <p class="muted">JSON конфиг (port, sni, keys…). REALITY-ключи генерируются при установке.</p>
      <textarea id="proto-cfg">${esc(cfg)}</textarea>
    `);
    $("#modal-ok").onclick = async () => {
      let parsed;
      try {
        parsed = JSON.parse($("#proto-cfg").value);
      } catch {
        toast("Невалидный JSON");
        return;
      }
      try {
        await api("/v1/protocols/" + id, {
          method: "PUT",
          body: { ...p, config: parsed },
        });
        closeModal();
        toast("Сохранено");
        loadProtocols();
      } catch (e) {
        toast(e.message);
      }
    };
  }

  async function applyProtocols() {
    try {
      await api("/v1/protocols/apply", { method: "POST" });
      toast("Конфиги применены, Xray перезапущен");
    } catch (e) {
      toast(e.message);
    }
  }

  async function loadSettings() {
    try {
      const sub = await api("/v1/settings/subscription");
      $("#set-base-url").value = sub.base_public_url || API;
      $("#set-sub-path").value = sub.subscription_path || "/sub/";
      const xr = await api("/v1/settings/xray");
      $("#set-xray-log").value = xr.log_level || "warning";
    } catch (e) {
      toast(e.message);
    }
  }

  async function saveSettings() {
    try {
      await api("/v1/settings/subscription", {
        method: "PUT",
        body: {
          base_public_url: $("#set-base-url").value.trim() || API,
          subscription_path: $("#set-sub-path").value.trim() || "/sub/",
          subscription_kind: "v2ray_base64",
        },
      });
      toast("Настройки сохранены");
    } catch (e) {
      toast(e.message);
    }
  }

  async function saveXraySettings() {
    try {
      await api("/v1/settings/xray", {
        method: "PUT",
        body: { log_level: $("#set-xray-log").value, api_listen: "0.0.0.0:10085" },
      });
      toast("Xray settings saved");
    } catch (e) {
      toast(e.message);
    }
  }

  function openModal(title, html) {
    $("#modal-title").textContent = title;
    $("#modal-body").innerHTML = html;
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

  async function boot() {
    showPage("dashboard");
    try {
      state.protocols = (await api("/v1/protocols")).protocols || [];
    } catch { /* ok */ }
  }

  function init() {
    $("#btn-login").addEventListener("click", login);
    $("#login-key").addEventListener("keydown", (e) => e.key === "Enter" && login());
    $("#btn-logout").addEventListener("click", logout);
    $$(".nav-btn").forEach((b) => b.addEventListener("click", () => showPage(b.dataset.page)));
    $("#btn-add-user").addEventListener("click", addUser);
    $("#btn-apply-protocols").addEventListener("click", applyProtocols);
    $("#btn-save-settings").addEventListener("click", saveSettings);
    $("#btn-save-xray").addEventListener("click", saveXraySettings);

    if (state.token) {
      api("/health", { noAuth: true }).then(() => {
        $("#view-login").classList.add("hidden");
        $("#view-app").classList.remove("hidden");
        boot();
      }).catch(() => logout());
    } else {
      $("#view-login").classList.remove("hidden");
    }
  }

  init();
})();
