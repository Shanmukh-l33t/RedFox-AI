// RedFox AI web UI: engagement list, live event feed, findings, reports.
const state = { current: null, ws: null, events: 0 };

const el = (sel) => document.querySelector(sel);
const esc = (s) => String(s ?? "").replace(/[&<>"]/g, (c) =>
  ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

async function api(path, options) {
  const res = await fetch(path, options);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json();
}

async function loadEngagements() {
  const list = await api("/api/engagements");
  const box = el("#engagements");
  if (!list.length) {
    box.innerHTML = `<div class="empty">No engagements yet. Create one with
      <code>redfox init scope.json</code>.</div>`;
    return;
  }
  box.innerHTML = list.map((e) => `
    <div class="eng ${e.id === state.current ? "active" : ""}" data-id="${e.id}">
      <b>${esc(e.name)}</b>
      <span>L${e.autonomy} · <span class="pill ${esc(e.status)}">${esc(e.status)}</span></span>
      <div><span><code>${esc(e.id)}</code></span></div>
    </div>`).join("");
  box.querySelectorAll(".eng").forEach((node) => {
    node.onclick = () => selectEngagement(node.dataset.id);
  });
}

async function selectEngagement(id) {
  state.current = id;
  await loadEngagements();
  const data = await api(`/api/engagements/${id}`);
  const s = data.summary;
  const findings = data.findings || [];
  el("#detail").innerHTML = `
    <div class="row">
      <div class="stat"><b>${s.findings.total}</b><span>findings</span></div>
      <div class="stat"><b>${s.findings.validated}</b><span>validated</span></div>
      <div class="stat"><b>${s.actions.allowed}</b><span>actions allowed</span></div>
      <div class="stat"><b>${s.actions.denied}</b><span>refused</span></div>
      <div class="stat"><b>${s.evidence}</b><span>evidence files</span></div>
      <div class="stat"><b>${s.audit.ok ? "OK" : "FAIL"}</b><span>audit chain</span></div>
    </div>
    <div class="row" style="gap:10px">
      <button data-act="run">Run / resume</button>
      <button data-act="halt">Pause</button>
      <a href="/api/engagements/${id}/report?fmt=html" target="_blank">
        <button>Open report</button></a>
      <a href="/api/engagements/${id}/report?fmt=sarif" target="_blank">
        <button>SARIF</button></a>
    </div>
    <h2>Scope</h2>
    <p><code>${esc(JSON.stringify(data.engagement.scope))}</code><br>
       operator <code>${esc(data.engagement.authorization.operator)}</code> ·
       authorization <code>${esc(data.engagement.authorization.authorization_ref)}</code> ·
       autonomy L${data.engagement.autonomy} · status
       <span class="pill ${esc(data.engagement.status)}">${esc(data.engagement.status)}</span></p>
    <h2>Live events</h2>
    <div id="feed"></div>
    <h2>Findings</h2>
    ${findings.length ? `<table><thead><tr><th>Severity</th><th>Finding</th>
      <th>Asset</th><th>Status</th><th>Evidence</th></tr></thead><tbody>
      ${findings.map((f) => `<tr>
        <td><span class="sev ${esc(f.severity)}">${esc(f.severity)}</span></td>
        <td>${esc(f.title)}</td>
        <td><code>${esc(f.location || f.asset)}</code></td>
        <td>${esc(f.status)}</td>
        <td>${(f.evidence_ids || []).map((e) => `<code>${esc(e)}</code>`).join(" ")}</td>
      </tr>`).join("")}</tbody></table>`
      : `<div class="empty">No findings recorded yet.</div>`}
  `;
  el("#detail").querySelector('[data-act="run"]').onclick = async () => {
    await api(`/api/engagements/${id}/run`, {
      method: "POST", headers: { "content-type": "application/json" },
      body: JSON.stringify({}),
    });
    poll();
  };
  el("#detail").querySelector('[data-act="halt"]').onclick = async () => {
    await api(`/api/engagements/${id}/halt`, { method: "POST" });
    poll();
  };
  connectStream(id);
  poll();
}

function connectStream(id) {
  if (state.ws) { try { state.ws.close(); } catch (e) {} }
  const ws = new WebSocket(`ws://${location.host}/ws/${id}`);
  state.ws = ws;
  ws.onmessage = (msg) => {
    const feed = el("#feed");
    if (!feed) return;
    const data = JSON.parse(msg.data);
    if (data.type === "status") {
      const pill = document.querySelector(`.eng[data-id="${id}"] .pill`);
      if (pill) { pill.textContent = data.status; pill.className = `pill ${data.status}`; }
      return;
    }
    const payload = data.payload || {};
    const line = `${(data.ts || "").slice(11, 19)}  ${data.type}` +
      (payload.tool ? `  ${payload.tool} → ${payload.target || ""}` : "") +
      (payload.reason ? `  (${payload.reason})` : "") +
      (payload.status ? `  [${payload.status}]` : "");
    feed.textContent += line + "\n";
    feed.scrollTop = feed.scrollHeight;
  };
  ws.onclose = () => { state.ws = null; };
}

async function poll() {
  if (!state.current) return;
  try {
    const data = await api(`/api/engagements/${state.current}`);
    const feed = el("#feed");
    if (feed) {
      const events = await api(`/api/engagements/${state.current}/events`);
      feed.textContent = events.map((e) => {
        const p = e.payload || {};
        return `${(e.ts || "").slice(11, 19)}  ${e.type}` +
          (p.tool ? `  ${p.tool} → ${p.target || ""}` : "") +
          (p.reason ? `  (${p.reason})` : "") +
          (p.status ? `  [${p.status}]` : "");
      }).join("\n");
      feed.scrollTop = feed.scrollHeight;
    }
    const pill = document.querySelector(`.eng[data-id="${state.current}"] .pill`);
    if (pill) {
      pill.textContent = data.engagement.status;
      pill.className = `pill ${data.engagement.status}`;
    }
  } catch (e) { /* transient */ }
}

el("#refresh").onclick = () => { loadEngagements(); poll(); };
el("#killBtn").onclick = async () => {
  await api("/api/kill", { method: "POST" });
  alert("Kill switch engaged. All agents halt.");
  loadEngagements();
};

loadEngagements();
setInterval(poll, 3000);