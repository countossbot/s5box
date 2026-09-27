'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

// --- 基础
async function api(path, opts = {}) {
  opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const r = await fetch('/api' + path, opts);
  if (r.status === 401) { toast('认证失败，请重新登录面板', 'err'); throw new Error('unauthorized'); }
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!r.ok) throw new Error((data && (data.detail || data.error)) || `HTTP ${r.status}`);
  return data;
}

// toast：kind = 'ok' | 'err' | 'warn'；右下角堆叠，自动消散
function toast(msg, kind = 'ok') {
  const d = document.createElement('div');
  d.className = 'toast' + (kind === 'ok' ? '' : ' ' + kind);
  d.textContent = msg;
  $('#toast').appendChild(d);
  const ttl = kind === 'err' ? 6000 : 3200;
  setTimeout(() => { d.classList.add('out'); setTimeout(() => d.remove(), 200); }, ttl);
}

const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtBytes = n => { n = n || 0; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + u[i]; };
const fmtAgo = ts => { if (!ts) return '—'; const s = Math.floor(Date.now() / 1000 - ts); if (s < 60) return s + '秒前'; if (s < 3600) return Math.floor(s / 60) + '分钟前'; if (s < 86400) return Math.floor(s / 3600) + '小时前'; return Math.floor(s / 86400) + '天前'; };
const fmtTime = ts => ts ? new Date(ts * 1000).toLocaleTimeString('zh-CN', { hour12: false }) : '—';

let busy = false;
async function guard(fn, msg) {
  if (busy) return toast('上一个操作还没完成', 'warn');
  busy = true;
  try { return await fn(); }
  catch (e) { toast((msg ? msg + '：' : '') + e.message, 'err'); }
  finally { busy = false; }
}

// 危险操作二次确认：原生 <dialog> 风格模态，焦点被约束在弹窗内
function confirmAction({ title, body, detail, confirmText = '确认删除', danger = true }) {
  return new Promise(resolve => {
    const host = $('#modal-host');
    const prev = document.activeElement;
    const overlay = document.createElement('div');
    overlay.className = 'overlay';
    overlay.innerHTML = `
      <div class="modal" role="alertdialog" aria-modal="true" aria-labelledby="cf-title" aria-describedby="cf-body">
        <h4 id="cf-title">${esc(title)}</h4>
        <p id="cf-body">${esc(body)}</p>
        ${detail ? `<div class="target">${esc(detail)}</div>` : ''}
        <div class="modal-actions">
          <button class="ghost" data-cf="cancel">取消</button>
          <button class="${danger ? 'danger' : 'primary'}" data-cf="ok">${esc(confirmText)}</button>
        </div>
      </div>`;
    host.appendChild(overlay);
    const okBtn = overlay.querySelector('[data-cf="ok"]');
    const cancelBtn = overlay.querySelector('[data-cf="cancel"]');
    cancelBtn.focus();
    const done = val => {
      document.removeEventListener('keydown', onKey, true);
      overlay.remove();
      if (prev && prev.isConnected) prev.focus();
      resolve(val);
    };
    const onKey = e => {
      if (e.key === 'Escape') { e.preventDefault(); done(false); }
      else if (e.key === 'Tab') { // 焦点圈定在弹窗内
        const f = [cancelBtn, okBtn];
        const i = f.indexOf(document.activeElement);
        e.preventDefault();
        f[(i + (e.shiftKey ? f.length - 1 : 1)) % f.length].focus();
      }
    };
    document.addEventListener('keydown', onKey, true);
    cancelBtn.onclick = () => done(false);
    okBtn.onclick = () => done(true);
    overlay.onclick = e => { if (e.target === overlay) done(false); };
  });
}

// 长耗时操作进行中的行内提示
function setLoading(el, text) {
  if (!el) return;
  if (text) { el.hidden = false; el.innerHTML = `<span class="spinner"></span>${esc(text)}`; }
  else { el.hidden = true; el.textContent = ''; }
}
// 给按钮加/去「进行中」状态（禁用 + 文字）
function setBusy(btn, on, busyText) {
  if (!btn) return;
  if (on) {
    btn.dataset.label = btn.textContent;
    btn.disabled = true;
    btn.setAttribute('aria-busy', 'true');
    if (busyText) btn.textContent = busyText;
    else btn.classList.add('btn-dots');
  } else {
    btn.disabled = false;
    btn.removeAttribute('aria-busy');
    if (btn.dataset.label) btn.textContent = btn.dataset.label;
    btn.classList.remove('btn-dots');
  }
}

// --- Tab（键盘方向键可在页签间切换）
const TAB_LIST = $$('#tabs button');
TAB_LIST.forEach(b => {
  b.onclick = () => activateTab(b.dataset.tab);
  b.onkeydown = e => {
    const i = TAB_LIST.indexOf(b), n = TAB_LIST.length;
    if (e.key === 'ArrowRight') { e.preventDefault(); const t = TAB_LIST[(i + 1) % n]; t.focus(); activateTab(t.dataset.tab); }
    if (e.key === 'ArrowLeft') { e.preventDefault(); const t = TAB_LIST[(i - 1 + n) % n]; t.focus(); activateTab(t.dataset.tab); }
  };
});
function activateTab(name) {
  $$('#tabs button').forEach(x => {
    const on = x.dataset.tab === name;
    x.classList.toggle('active', on);
    x.setAttribute('aria-selected', String(on));
    x.tabIndex = on ? 0 : -1;
  });
  $$('.tab').forEach(s => s.classList.toggle('active', s.id === 'tab-' + name));
  loadTab(name);
}
function loadTab(name) {
  ({ overview: loadOverview, spaces: loadSpaces, nodes: loadNodes, logs: loadLogs, settings: loadSettings }[name] || (() => {}))();
}

// --- 概览
function bars(el, obj, total) {
  const ents = Object.entries(obj || {});
  if (!ents.length) return el.innerHTML = '<div class="empty"><strong>还没有连接记录</strong>配置好客户端后，这里会显示随机命中分布。</div>';
  const max = Math.max(...ents.map(([, v]) => v), 1);
  el.innerHTML = ents.map(([k, v]) => `
    <div class="bar-row">
      <span class="bar-name" title="${esc(k)}">${esc(k)}</span>
      <div class="bar"><i style="width:${Math.max((v / max * 100), 3).toFixed(1)}%"></i></div>
      <span class="bar-num">${v}${total ? ' · ' + (v / total * 100).toFixed(0) + '%' : ''}</span>
    </div>`).join('');
}
function skeleton(rows = 4) {
  return `<div class="skeleton">${Array.from({ length: rows }, () => '<div class="sk-row"></div>').join('')}</div>`;
}
function errBox(msg, retryId) {
  return `<div class="err-box"><span>加载失败：${esc(msg)}</span>${retryId ? `<button class="ghost tiny" data-retry="${retryId}">重试</button>` : ''}</div>`;
}
async function loadOverview() {
  try {
    const o = await api('/overview');
    const g = o.registry, p = o.proxy, d = o.random.distribution;
    $('#conn-badge').textContent = `活跃 ${p.active}`;
    $('#conn-badge').classList.toggle('on', p.active > 0);
    const bad = g.cooling + g.deleted;
    $('#ov-cards').innerHTML = [
      ['订阅空间', g.spaces, `${g.spaces_active} 个有可用节点`, ''],
      ['节点总数', g.nodes, `健康 ${g.healthy} · 未探测 ${g.unknown}`, ''],
      ['已淘汰', bad, `失败 ${g.cooling} · 自动删除 ${g.deleted}`, bad > 0 ? 'warn' : ''],
      ['活跃连接', p.active, `累计 ${p.total} · 错误 ${p.errors}`, p.errors > 0 ? 'bad' : ''],
      ['流量', fmtBytes(p.bytes_down), `上行 ${fmtBytes(p.bytes_up)}`, ''],
      ['外部端口', `S${p.socks_port}`, `HTTP ${p.http_port}${p.auth ? ' · 已开启认证' : ''}`, ''],
      ['sing-box', o.singbox, `运行 ${Math.floor(o.uptime / 60)} 分钟`, ''],
      ['随机模式', o.random.weight_mode === 'space' ? '空间等权' : '节点数加权', `样本 ${d.sampled} 次 · 成功 ${d.ok}/${d.sampled}`, ''],
    ].map(([k, v, s, cls]) => `<div class="card ${cls}"><div class="k">${k}</div><div class="v">${esc(v)}</div><div class="s">${esc(s)}</div></div>`).join('');

    bars($('#dist-space'), d.by_space, d.sampled);
    bars($('#dist-node'), d.by_node, d.sampled);
    const tb = $('#inst-table tbody');
    tb.innerHTML = o.instances.length ? o.instances.map(i => `
      <tr><td>#${i.space_id} ${esc(i.name)}</td><td class="mono">127.0.0.1:${i.socks_port}</td>
      <td><span class="st ${i.alive ? 'healthy' : 'deleted'}">${i.alive ? '运行中' : '未运行'}</span></td></tr>`).join('')
      : '<tr><td colspan="3" class="empty"><strong>还没有订阅空间</strong>在「订阅空间」页添加后，这里会显示 sing-box 实例。</td></tr>';
  } catch (e) {
    $('#ov-cards').innerHTML = errBox(e.message, 'overview');
    $('#dist-space').innerHTML = ''; $('#dist-node').innerHTML = '';
    $('#inst-table tbody').innerHTML = '<tr><td colspan="3" class="empty">加载失败</td></tr>';
  }
}

// ---------------------------------------------------------------- 空间
async function loadSpaces() {
  const list = await api('/spaces');
  const tb = $('#sp-table tbody');
  tb.innerHTML = list.length ? list.map(s => {
    const c = s.counts;
    return `<tr>
      <td class="mono">${s.id}</td>
      <td><input value="${esc(s.name)}" data-act="name" data-id="${s.id}" style="width:150px" aria-label="空间名称"></td>
      <td><div class="btn-row">
            <span class="st healthy" title="健康">${c.healthy}</span>
            <span class="st unknown" title="未探测">${c.unknown}</span>
            <span class="st cooling" title="探测失败">${c.cooling}</span>
            <span class="st deleted" title="已删除">${c.deleted}</span>
          </div>
          <div class="mono" style="color:var(--dim);margin-top:3px">共 ${c.total}</div></td>
      <td>
        <input value="${esc(s.url)}" data-act="url" data-id="${s.id}" style="width:260px" spellcheck="false" aria-label="订阅链接">
        <div style="margin-top:4px;font-size:11.5px;color:${s.last_refresh_ok ? 'var(--dim)' : 'var(--bad)'}">
          ${s.last_refresh_ok ? '✓ ' : '✗ '}${fmtAgo(s.last_refresh_at)} ${s.last_refresh_error ? '· ' + esc(String(s.last_refresh_error).slice(0, 90)) : ''}
        </div>
        <div style="margin-top:3px">
          <label>刷新间隔 <input type="number" value="${s.refresh_interval}" data-act="refresh_interval" data-id="${s.id}" style="width:80px" aria-label="刷新间隔（秒）"> 秒</label>
        </div>
      </td>
      <td>
        <select data-act="weight_mode" data-id="${s.id}" aria-label="权重模式">
          <option value="space" ${s.weight_mode === 'space' ? 'selected' : ''}>空间等权</option>
          <option value="node" ${s.weight_mode === 'node' ? 'selected' : ''}>节点加权</option>
        </select>
        <div class="mono" style="color:var(--dim);margin-top:4px">私网 socks :${s.socks_port ?? '—'}</div>
      </td>
      <td class="mono" style="font-size:12px">${fmtAgo(s.last_refresh_at)}</td>
      <td>
        <div class="btn-row">
          <button class="tiny ghost" data-act="save" data-id="${s.id}">保存</button>
          <button class="tiny ghost" data-act="refresh" data-id="${s.id}">刷新</button>
          <button class="tiny ghost" data-act="toggle" data-id="${s.id}" data-src="${s.enabled ? '停用' : '启用'}">${s.enabled ? '停用' : '启用'}</button>
          <button class="tiny danger ghost" data-act="del" data-id="${s.id}" data-src="${esc(s.name)}">删除</button>
        </div>
      </td></tr>`;
  }).join('') : '<tr><td colspan="7" class="empty"><strong>还没有订阅空间</strong>在下面填入订阅链接，添加后即可开始拉取节点。</td></tr>';
  $('#f-space').innerHTML = '<option value="">全部空间</option>' +
    list.map(s => `<option value="${s.id}">#${s.id} ${esc(s.name)}</option>`).join('');
}

function rowFields(id) {
  const tr = $(`[data-id="${id}"][data-act="name"]`)?.closest('tr');
  const get = a => tr?.querySelector(`[data-act="${a}"]`)?.value;
  return { name: get('name'), url: get('url'), refresh_interval: +get('refresh_interval') || 1800, weight_mode: get('weight_mode') };
}
$('#sp-table').addEventListener('click', async e => {
  const b = e.target.closest('button[data-act]'); if (!b) return;
  const id = +b.dataset.id, act = b.dataset.act;
  await guard(async () => {
    if (act === 'save') {
      setBusy(b, true);
      try { await api('/spaces/' + id, { method: 'PATCH', body: JSON.stringify(rowFields(id)) }); toast('已保存'); }
      finally { setBusy(b, false); }
    }
    if (act === 'refresh') {
      setBusy(b, true, '刷新中…');
      try {
        toast('正在拉取订阅并解析，可能需要十几秒…');
        const r = await api(`/spaces/${id}/refresh`, { method: 'POST' });
        toast(r.ok ? `已刷新：解析 ${r.parsed} 个 → 保留 ${r.accepted} 个` : '刷新失败：' + r.error, r.ok ? 'ok' : 'err');
      } finally { setBusy(b, false); }
    }
    if (act === 'toggle') {
      const enabled = b.dataset.src === '停用'; // data-src 记录的是「当前动作」，停用即转为 enabled=false
      const toDisable = !enabled;
      if (toDisable && !(await confirmAction({
        title: '停用这个订阅空间？',
        body: '停用后它的 sing-box 实例与全部节点会退出负载池；随时可以再启用，数据不会删除。',
        confirmText: '确认停用', danger: true,
      }))) return;
      setBusy(b, true);
      try {
        await api('/spaces/' + id, { method: 'PATCH', body: JSON.stringify({ enabled }) });
        toast(enabled ? '已启用' : '已停用');
      } finally { setBusy(b, false); }
    }
    if (act === 'del') {
      if (!(await confirmAction({
        title: '删除订阅空间？',
        body: '此操作不可撤销：该空间的 sing-box 实例会被停用，它的全部节点记录会一并删除。',
        detail: `#${id} ${b.dataset.src || ''}`,
        confirmText: '永久删除',
      }))) return;
      setBusy(b, true, '删除中…');
      try { await api('/spaces/' + id, { method: 'DELETE' }); toast('空间已删除'); }
      finally { setBusy(b, false); }
    }
    await loadSpaces();
  });
});
$('#btn-add-space').onclick = () => guard(async () => {
  const url = $('#sp-url').value.trim(); if (!url) return toast('请填订阅链接', 'warn');
  const btn = $('#btn-add-space'); setBusy(btn, true, '拉取中…');
  try {
    toast('正在拉取并解析，可能需要十几秒…');
    const r = await api('/spaces', { method: 'POST', body: JSON.stringify({ url, name: $('#sp-name').value.trim() }) });
    const q = r.refresh;
    toast(q.ok ? `空间 #${r.id} 已创建：解析 ${q.parsed} 个 → 接受 ${q.accepted} 个` : `空间已建但拉取失败：${q.error}`, q.ok ? 'ok' : 'err');
    $('#sp-url').value = ''; $('#sp-name').value = '';
    await loadSpaces();
  } finally { setBusy(btn, false); }
}, '添加失败');
$('#btn-bulk').onclick = () => guard(async () => {
  const urls = $('#bulk-urls').value.trim(); if (!urls) return toast('请粘贴链接', 'warn');
  const btn = $('#btn-bulk'); setBusy(btn, true, '批量创建中…');
  try {
    const out = await api('/spaces/bulk', { method: 'POST', body: JSON.stringify({ urls }) });
    const ok = out.filter(x => x.id).length;
    toast(`完成：成功 ${ok} / ${out.length}`, ok === 0 ? 'err' : 'ok');
    $('#bulk-urls').value = ''; await loadSpaces();
  } finally { setBusy(btn, false); }
}, '批量创建失败');

// --- 节点
let nodeCache = [];
async function loadNodes() {
  const tb = $('#node-table tbody');
  const p = new URLSearchParams();
  if ($('#f-space').value) p.set('space_id', $('#f-space').value);
  if ($('#f-state').value && $('#f-state').value !== 'all') p.set('state', $('#f-state').value);
  if ($('#f-q').value.trim()) p.set('q', $('#f-q').value.trim());
  setLoading($('#node-loading'), '正在加载节点…');
  try {
    nodeCache = await api('/nodes?' + p);
    $('#node-count').textContent = `共 ${nodeCache.length} 个`;
    const spaces = Object.fromEntries((await api('/spaces')).map(s => [s.id, s.name]));
    const filtered = $('#f-space').value || $('#f-state').value !== 'all' || $('#f-q').value.trim();
    tb.innerHTML = nodeCache.length ? nodeCache.map(n => `<tr data-nid="${n.id}">
    <td><input type="checkbox" class="chk-node" value="${n.id}" aria-label="选择节点 ${esc(n.name)}"></td>
    <td class="mono" style="font-size:12px">#${n.space_id} ${esc(spaces[n.space_id] || '')}</td>
    <td title="${esc(n.deletion_reason || '')}">${esc(n.name)}</td>
    <td class="mono" style="font-size:12px">${esc(n.protocol)}</td>
    <td class="addr" title="${esc(n.host)}:${n.port}">${esc(n.host)}:${n.port}</td>
    <td><span class="st ${esc(n.state)}">${STATE_LABEL[n.state] || n.state}</span></td>
    <td class="mono" style="font-size:12px">${n.delay_ms ? n.delay_ms + 'ms' : '—'}</td>
    <td class="addr mono" title="${esc(n.exit_ip || '')}">${esc(n.exit_ip || '—')}</td>
    <td class="mono" style="font-size:12px;color:${n.fail_count ? 'var(--bad)' : 'var(--dim)'}">${n.fail_count}</td>
    <td style="text-align:right"><div class="btn-row" style="justify-content:flex-end">
      <button class="tiny ghost" data-nact="probe" data-nid="${n.id}">探测</button>
      ${n.state === 'deleted' ? `<button class="tiny ghost" data-nact="revive" data-nid="${n.id}">复活</button>` : ''}
      <button class="tiny danger ghost" data-nact="delete" data-nid="${n.id}">删除</button>
    </div></td></tr>`).join('')
      : `<tr><td colspan="10" class="empty"><strong>${filtered ? '没有匹配的节点' : '还没有节点'}</strong>${filtered ? '换个筛选条件或清空搜索词试试。' : '添加订阅空间并刷新后，节点会自动出现在这里。'}</td></tr>`;
    syncSelCount();
  } catch (e) {
    tb.innerHTML = `<tr><td colspan="10">${errBox(e.message, 'nodes')}</td></tr>`;
    $('#node-count').textContent = '';
  } finally { setLoading($('#node-loading'), null); }
}
// 节点被删除时是**物理删除**，列表里不会再有 deleted 行，
// 所以这里不再需要"已删除"标签；retry_pending 是"本轮失败待重测"。
const STATE_LABEL = { healthy: '健康', unknown: '未探测', cooling: '探测失败',
                      retry_pending: '待重测', deleted: '已删除' };
function syncSelCount() {
  const all = $$('.chk-node'), sel = all.filter(c => c.checked).length;
  $('#node-sel').textContent = sel ? `已选 ${sel} 个` : '';
  const chkAll = $('#chk-all');
  if (chkAll) { chkAll.checked = all.length > 0 && sel === all.length; chkAll.indeterminate = sel > 0 && sel < all.length; }
  ['#btn-bulk-delete', '#btn-bulk-revive'].forEach(s => { const b = $(s); if (b) b.disabled = sel === 0; });
}

// ---------------------------------------------------------------- 节点
$('#f-space').onchange = $('#f-state').onchange = loadNodes;
let qt; $('#f-q').oninput = () => { clearTimeout(qt); qt = setTimeout(loadNodes, 300); };

$('#chk-all').onchange = e => { $$('.chk-node').forEach(c => { c.checked = e.target.checked; c.closest('tr').classList.toggle('selected', e.target.checked); }); syncSelCount(); };
$('#node-table').addEventListener('change', e => {
  if (e.target.classList.contains('chk-node')) { e.target.closest('tr').classList.toggle('selected', e.target.checked); syncSelCount(); }
});

$('#node-table').addEventListener('click', async e => {
  const b = e.target.closest('button[data-nact]'); if (!b) return;
  const nid = +b.dataset.nid, act = b.dataset.nact;
  const row = b.closest('tr');
  const name = row?.children[2]?.textContent.trim() || `#${nid}`;
  if (act === 'delete') {
    const ok = await confirmAction({
      title: '删除这个节点？',
      body: '不可撤销：节点会从随机负载池中移除，后续不再被选中。',
      detail: name,
      confirmText: '永久删除',
    });
    if (!ok) return;
  }
  await guard(async () => {
    setBusy(b, true);
    try {
      if (act === 'probe') {
        const r = await api(`/nodes/${nid}/probe`, { method: 'POST' });
        toast(r.ok ? `可用 ${r.delay_ms}ms · 出口 ${r.exit_ip || '?'}` : `不可用：${r.error}`, r.ok ? 'ok' : 'err');
      }
      if (act === 'delete') { await api(`/nodes/${nid}/delete`, { method: 'POST' }); toast('已从随机池移除'); }
      if (act === 'revive') { await api(`/nodes/${nid}/revive`, { method: 'POST' }); toast('已复活，等待下次探测'); }
    } finally { setBusy(b, false); }
    await loadNodes();
  }, act === 'probe' ? '探测失败' : '操作失败');
});

async function bulk(action) {
  const ids = $$('.chk-node').filter(c => c.checked).map(c => +c.value);
  if (!ids.length) return toast('先勾选节点', 'warn');
  const label = action === 'delete' ? '删除' : action === 'revive' ? '复活' : '探测';
  if (action === 'delete') {
    const ok = await confirmAction({
      title: `删除选中的 ${ids.length} 个节点？`,
      body: '不可撤销：这些节点会从随机负载池中永久移除。',
      confirmText: `永久删除 ${ids.length} 个`,
    });
    if (!ok) return;
  }
  const btn = action === 'delete' ? $('#btn-bulk-delete') : action === 'revive' ? $('#btn-bulk-revive') : $('#btn-probe-all');
  await guard(async () => {
    setBusy(btn, true, `${label}中…`);
    try {
      await api('/nodes/bulk', { method: 'POST', body: JSON.stringify({ ids, action }) });
      toast(`已${label} ${ids.length} 个节点`);
    } finally { setBusy(btn, false); }
    await loadNodes();
  }, `${label}失败`);
}
$('#btn-bulk-delete').onclick = () => bulk('delete');
$('#btn-bulk-revive').onclick = () => bulk('revive');
$('#btn-probe-all').onclick = () => guard(async () => {
  const btn = $('#btn-probe-all');
  const ok = await confirmAction({
    title: '立即全量探测？',
    body: '会对所有空间的所有节点重新探测，节点多时可能需要几分钟，期间面板仍可正常浏览。',
    confirmText: '开始探测', danger: false,
  });
  if (!ok) return;
  setBusy(btn, true, '探测中…');
  setLoading($('#node-loading'), '正在全量探测，节点多时可能需要几分钟，请勿关闭页面…');
  try {
    const r = await api('/probe/run', { method: 'POST' });
    const okN = r.reduce((a, x) => a + (x.ok || 0), 0), del = r.reduce((a, x) => a + (x.deleted || 0), 0);
    toast(`探测完成：可用 ${okN}${del ? `，自动删除 ${del}` : ''}`, 'ok');
  } finally { setBusy(btn, false); setLoading($('#node-loading'), null); }
  await loadNodes();
}, '探测失败');

// --- 日志
async function loadLogs() {
  setLoading($('#log-loading'), '正在加载日志…');
  try {
    const list = await api('/logs?limit=200');
    $('#log-table tbody').innerHTML = list.length ? list.map(l => `<tr>
      <td class="mono" style="font-size:12px" title="${esc(new Date(l.ts * 1000).toLocaleString('zh-CN'))}">${fmtTime(l.ts)}</td>
      <td class="mono" style="font-size:12px">${esc(l.client || '—')}</td>
      <td class="mono" style="font-size:12px">${esc(l.proto || '—')}</td>
      <td class="addr" title="${esc(l.target || '')}">${esc(l.target || '—')}</td>
      <td>${l.space_id ? `#${l.space_id} ${esc(l.space_name || '')}` : '—'}</td>
      <td>${l.node_id ? `#${l.node_id} ${esc(l.node_name || '')}` : '—'}</td>
      <td><span class="st ${l.ok ? 'healthy' : 'deleted'}">${l.ok ? '成功' : '失败'}</span></td>
      <td style="font-size:11.5px;color:var(--dim)">${esc(l.detail || l.error || '')}</td>
    </tr>`).join('')
      : '<tr><td colspan="8" class="empty"><strong>还没有连接记录</strong>配置客户端指向本代理后，每次连接都会记录随机命中结果。</td></tr>';
  } catch (e) {
    $('#log-table tbody').innerHTML = `<tr><td colspan="8">${errBox(e.message, 'logs')}</td></tr>`;
  } finally { setLoading($('#log-loading'), null); }
}
$('#btn-log-refresh').onclick = loadLogs;

// ---------------------------------------------------------------- 设置
const SET_DEFS = {
  'set-probe': [
    ['probe_interval', '探测周期（秒）', '一轮全空间探测的间隔'],
    ['probe_timeout', '单节点超时（秒）'],
    ['probe_url', '探测目标 URL', '默认 https://httpbin.org/ip，直接取出口 IP'],
    ['probe_exit_ip_from_body', '从探测响应体解析出口 IP', 'true / false'],
    ['probe_retry_failed_once', '全轮结束后重测失败的节点一次', 'true=仍失败才删除'],
    ['failure_threshold', '连续失败多少次自动删除', '默认 3'],
    ['auto_delete', '探测失败自动删除节点', 'true / false'],
    ['probe_fallback_urls', '备用探测 URL（逗号分隔）', '主 URL 不可达时回退，只试第一个'],
    ['probe_round_budget', '单轮探测总时限（秒）', '节点很多时防止一轮跑太久把自己卡住'],
    ['probe_exit_ip', '探测时查询出口 IP', 'true / false'],
  ],
  'set-random': [
    ['weight_mode', '随机权重模式', 'space=每个空间等概率；node=按健康节点数加权'],
    ['max_connections', '最大并发连接数', '超出直接拒绝'],
    ['connect_retry', '握手失败换空间重试次数'],
    ['proxy_auth_b64', '代理认证（base64 的 user:pass）', '留空 = 不认证'],
    ['subscription_ua', '拉取订阅的 User-Agent'],
  ],
  'set-filter': [
    ['filter_protocols', '保留的协议（逗号分隔）'],
    ['filter_port_blacklist', '丢弃的端口（逗号分隔）'],
    ['filter_exclude_keywords', '节点名排除关键词（逗号分隔）'],
    ['filter_max_delay_ms', '延迟高于此值视为不合格（0=关闭）'],
    ['filter_max_nodes_per_space', '每空间节点容量上限', '默认 100，超出按"最差优先"淘汰'],
    ['node_cap_evict_strategy', '淘汰策略', 'worst=先删失败的/最慢的/最久未成功的；oldest=按加入时间 FIFO'],
    ['region_filter_mode', '地区过滤模式', 'off=不启用；whitelist=只保留列表内；blacklist=丢弃列表内'],
    ['region_filter_list', '地区列表（逗号分隔的地区码）', '如 HK,TW,JP,SG,US,KR,MO'],
    ['region_filter_unknown', '无法识别地区时', 'keep=保留；drop=丢弃'],
  ],
};
async function loadSettings() {
  const host = $('#set-probe').parentElement;
  const boxes = Object.keys(SET_DEFS);
  try {
    const s = await api('/settings');
    for (const [box, defs] of Object.entries(SET_DEFS)) {
      $('#' + box).innerHTML = defs.map(([k, label, hint]) => `
        <div class="set-item">
          <label for="set-${k}">${esc(label)}</label>
          <input id="set-${k}" data-key="${k}" value="${esc(s[k] ?? '')}">
          ${hint ? `<span class="hint">${esc(hint)}</span>` : ''}
          <span class="hint mono">${k}</span>
        </div>`).join('');
    }
    $('#save-msg').textContent = '';
  } catch (e) {
    boxes.forEach(b => $('#' + b).innerHTML = '');
    host.insertAdjacentHTML('afterbegin', errBox(e.message));
  }
}
$('#btn-save-settings').onclick = async () => {
  const btn = $('#btn-save-settings');
  // 收集所有带 data-key 的输入（含 select），空值保持原样提交
  const payload = {};
  $$('[data-key]').forEach(i => { payload[i.dataset.key] = i.value; });
  if (!Object.keys(payload).length) return toast('没有可保存的字段', 'warn');
  setBusy(btn, true, '保存中…');
  $('#save-msg').className = 'save-msg';
  $('#save-msg').textContent = '正在保存…';
  try {
    await api('/settings', { method: 'PUT', body: JSON.stringify(payload) });
    toast('设置已保存');

    $('#save-msg').textContent = '✓ 已保存 ' + new Date().toLocaleTimeString('zh-CN', { hour12: false });
    setTimeout(() => { if ($('#save-msg').classList.contains('ok')) $('#save-msg').textContent = ''; }, 5000);
  } catch (e) {
    $('#save-msg').className = 'save-msg err';
    $('#save-msg').textContent = '保存失败：' + e.message;
    toast('保存失败：' + e.message, 'err');
  } finally { setBusy(btn, false); }
};

// 重试按钮（错误态内联）
document.addEventListener('click', e => {
  const b = e.target.closest('[data-retry]'); if (!b) return;
  loadTab(b.dataset.retry);
});

// --- 顶栏刷新全部订阅
$('#btn-refresh-all').onclick = () => guard(async () => {
  const btn = $('#btn-refresh-all');
  const ok = await confirmAction({
    title: '刷新全部订阅？',
    body: '会重新拉取每个订阅空间的链接并按当前过滤/容量策略同步节点，可能需要十几秒。',
    confirmText: '开始刷新', danger: false,
  });
  if (!ok) return;
  setBusy(btn, true, '刷新中…');
  toast('正在刷新所有空间的订阅…');
  try {
    const out = await api('/refresh-all', { method: 'POST' });
    const okN = out.filter(x => x.ok).length;
    toast(`完成：${okN}/${out.length} 个空间刷新成功`, okN === 0 ? 'err' : 'ok');
    loadTab($$('#tabs button.active')[0].dataset.tab);
  } finally { setBusy(btn, false); }
}, '刷新失败');

// --- 启动 + 顶栏活跃连接轮询
activateTab('overview');
loadSpaces();
setInterval(async () => {
  const activeTab = $$('#tabs button.active')[0]?.dataset.tab;
  if (activeTab !== 'overview') {
    try {
      const o = await api('/overview');
      $('#conn-badge').textContent = `活跃 ${o.proxy.active}`;
      $('#conn-badge').classList.toggle('on', o.proxy.active > 0);
    } catch { /* 静默：顶栏轮询失败不打扰用户 */ }
  }
}, 5000);

// 探测进行中：每 5 秒刷新概览与顶栏，让「随机分布/节点数」跟着变
let lastProbeRunning = false;
setInterval(async () => {
  try {
    const o = await api('/overview');
    $('#conn-badge').textContent = `活跃 ${o.proxy.active}`;
    $('#conn-badge').classList.toggle('on', o.proxy.active > 0);
    const running = !!o.probe.running;
    if (running !== lastProbeRunning) {
      lastProbeRunning = running;
      toast(running ? '后台正在全量探测…' : '后台探测已结束', running ? 'warn' : 'ok');
    }
    if ($$('#tabs button.active')[0]?.dataset.tab === 'overview') loadOverview();
  } catch { /* 静默：轮询失败不打扰用户 */ }
}, 5000);
