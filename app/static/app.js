'use strict';
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];

// ---------------------------------------------------------------- 基础
async function api(path, opts = {}) {
  opts.headers = { 'Content-Type': 'application/json', ...(opts.headers || {}) };
  const r = await fetch('/api' + path, opts);
  if (r.status === 401) { toast('认证失败，请重新登录面板', true); throw new Error('unauthorized'); }
  const text = await r.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = { raw: text }; }
  if (!r.ok) throw new Error((data && (data.detail || data.error)) || `HTTP ${r.status}`);
  return data;
}
function toast(msg, err = false) {
  const d = document.createElement('div');
  d.className = 'toast' + (err ? ' err' : '');
  d.textContent = msg;
  $('#toast').appendChild(d);
  setTimeout(() => d.remove(), err ? 6000 : 3200);
}
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
const fmtBytes = n => { n = n || 0; const u = ['B', 'KB', 'MB', 'GB', 'TB']; let i = 0; while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; } return n.toFixed(i ? 1 : 0) + u[i]; };
const fmtAgo = ts => { if (!ts) return '—'; const s = Math.floor(Date.now() / 1000 - ts); if (s < 60) return s + '秒前'; if (s < 3600) return Math.floor(s / 60) + '分钟前'; if (s < 86400) return Math.floor(s / 3600) + '小时前'; return Math.floor(s / 86400) + '天前'; };
const fmtTime = ts => ts ? new Date(ts * 1000).toLocaleTimeString('zh-CN', { hour12: false }) : '—';
let busy = false;
async function guard(fn, msg) {
  if (busy) return toast('上一个操作还没完成', true);
  busy = true;
  try { return await fn(); }
  catch (e) { toast((msg ? msg + '：' : '') + e.message, true); }
  finally { busy = false; }
}

// ---------------------------------------------------------------- Tab
$$('#tabs button').forEach(b => b.onclick = () => {
  $$('#tabs button').forEach(x => x.classList.toggle('active', x === b));
  $$('.tab').forEach(s => s.classList.toggle('active', s.id === 'tab-' + b.dataset.tab));
  loadTab(b.dataset.tab);
});
function loadTab(name) {
  ({ overview: loadOverview, spaces: loadSpaces, nodes: loadNodes, logs: loadLogs, settings: loadSettings }[name] || (() => {}))();
}

// ---------------------------------------------------------------- 概览
function bars(el, obj, total) {
  const ents = Object.entries(obj || {});
  if (!ents.length) return el.innerHTML = '<div class="empty">还没有连接记录。配置好客户端后这里会显示随机分布。</div>';
  const max = Math.max(...ents.map(([, v]) => v), 1);
  el.innerHTML = ents.map(([k, v]) => `
    <div class="bar-row">
      <span title="${esc(k)}">${esc(k)}</span>
      <div class="bar-track"><div class="bar-fill" style="width:${(v / max * 100).toFixed(1)}%"></div></div>
      <span class="bar-num">${v}${total ? ' · ' + (v / total * 100).toFixed(0) + '%' : ''}</span>
    </div>`).join('');
}
async function loadOverview() {
  const o = await api('/overview');
  const g = o.registry, p = o.proxy, d = o.random.distribution;
  $('#conn-badge').textContent = `活跃 ${p.active}`;
  $('#ov-cards').innerHTML = [
    ['订阅空间', g.spaces, `${g.spaces_active} 个有可用节点`],
    ['节点总数', g.nodes, `健康 ${g.healthy} · 未探测 ${g.unknown}`],
    ['已淘汰', g.cooling + g.deleted, `失败 ${g.cooling} · 自动删除 ${g.deleted}`],
    ['活跃连接', p.active, `累计 ${p.total} · 错误 ${p.errors}`],
    ['流量', fmtBytes(p.bytes_down), `上行 ${fmtBytes(p.bytes_up)}`],
    ['外部端口', `S${o.proxy.socks_port}`, `HTTP ${o.proxy.http_port}${p.auth ? ' · 已开启认证' : ''}`],
    ['sing-box', o.singbox, `运行 ${Math.floor(o.uptime / 60)} 分钟`],
    ['随机模式', o.random.weight_mode === 'space' ? '空间等权' : '节点数加权', `样本 ${d.sampled} 次 · 成功 ${d.ok}/${d.sampled}`],
  ].map(([k, v, s]) => `<div class="card"><div class="k">${k}</div><div class="v">${esc(v)}</div><div class="s">${esc(s)}</div></div>`).join('');

  bars($('#dist-space'), d.by_space, d.sampled);
  bars($('#dist-node'), d.by_node, d.sampled);
  const tb = $('#inst-table tbody');
  tb.innerHTML = o.instances.length ? o.instances.map(i => `
    <tr><td>#${i.space_id} ${esc(i.name)}</td><td class="mono">127.0.0.1:${i.socks_port}</td>
    <td><span class="st ${i.alive ? 'healthy' : 'deleted'}">${i.alive ? '运行中' : '未运行'}</span></td></tr>`).join('')
    : '<tr><td colspan="3" class="empty">还没有空间</td></tr>';
}

// ---------------------------------------------------------------- 空间
async function loadSpaces() {
  const list = await api('/spaces');
  const tb = $('#sp-table tbody');
  tb.innerHTML = list.length ? list.map(s => {
    const c = s.counts;
    return `<tr>
      <td class="mono">${s.id}</td>
      <td><input value="${esc(s.name)}" data-act="name" data-id="${s.id}" style="width:150px"></td>
      <td><span class="st healthy">${c.healthy}</span> <span class="st unknown">${c.unknown}</span>
          <span class="st cooling">${c.cooling}</span> <span class="st deleted">${c.deleted}</span>
          <div class="mono" style="color:var(--dim);margin-top:3px">共 ${c.total}</div></td>
      <td>
        <input value="${esc(s.url)}" data-act="url" data-id="${s.id}" style="width:260px" spellcheck="false">
        <div style="margin-top:4px;font-size:11.5px;color:${s.last_refresh_ok ? 'var(--dim)' : 'var(--bad)'}">
          ${s.last_refresh_ok ? '✓ ' : '✗ '}${fmtAgo(s.last_refresh_at)} ${s.last_refresh_error ? '· ' + esc(s.last_refresh_error.slice(0, 90)) : ''}
        </div>
        <div style="margin-top:3px">
          刷新间隔 <input type="number" value="${s.refresh_interval}" data-act="refresh_interval" data-id="${s.id}" style="width:80px"> 秒
        </div>
      </td>
      <td>
        <select data-act="weight_mode" data-id="${s.id}">
          <option value="space" ${s.weight_mode === 'space' ? 'selected' : ''}>空间等权</option>
          <option value="node" ${s.weight_mode === 'node' ? 'selected' : ''}>节点加权</option>
        </select>
        <div class="mono" style="color:var(--dim);margin-top:4px">私网 socks :${s.socks_port ?? '—'}</div>
      </td>
      <td class="mono" style="font-size:12px">${fmtAgo(s.last_refresh_at)}</td>
      <td style="white-space:nowrap">
        <button class="tiny ghost" data-act="save" data-id="${s.id}">保存</button>
        <button class="tiny ghost" data-act="refresh" data-id="${s.id}">刷新</button>
        <button class="tiny ghost" data-act="toggle" data-id="${s.id}">${s.enabled ? '停用' : '启用'}</button>
        <button class="tiny danger ghost" data-act="del" data-id="${s.id}">删除</button>
      </td></tr>`;
  }).join('') : '<tr><td colspan="7" class="empty">还没有订阅空间，先在上面添加一个。</td></tr>';
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
    if (act === 'save') { await api('/spaces/' + id, { method: 'PATCH', body: JSON.stringify(rowFields(id)) }); toast('已保存'); }
    if (act === 'refresh') { const r = await api(`/spaces/${id}/refresh`, { method: 'POST' }); toast(r.ok ? `已刷新：解析 ${r.parsed} 个 → 保留 ${r.accepted} 个` : '刷新失败：' + r.error, !r.ok); }
    if (act === 'toggle') {
      const tr = b.closest('tr'); const enabled = /启用/.test(b.textContent);
      await api('/spaces/' + id, { method: 'PATCH', body: JSON.stringify({ enabled }) }); toast(enabled ? '已启用' : '已停用');
    }
    if (act === 'del') { if (!confirm('删除这个空间？它的所有节点记录会一并清除。')) return; await api('/spaces/' + id, { method: 'DELETE' }); toast('已删除'); }
    await loadSpaces();
  });
});
$('#btn-add-space').onclick = () => guard(async () => {
  const url = $('#sp-url').value.trim(); if (!url) return toast('请填订阅链接', true);
  toast('正在拉取并解析，可能需要十几秒…');
  const r = await api('/spaces', { method: 'POST', body: JSON.stringify({ url, name: $('#sp-name').value.trim() }) });
  const q = r.refresh;
  toast(q.ok ? `空间 #${r.id} 已创建：解析 ${q.parsed} 个 → 接受 ${q.accepted} 个` : `空间已建但拉取失败：${q.error}`, !q.ok);
  $('#sp-url').value = ''; $('#sp-name').value = '';
  await loadSpaces();
}, '添加失败');
$('#btn-bulk').onclick = () => guard(async () => {
  const urls = $('#bulk-urls').value.trim(); if (!urls) return toast('请粘贴链接', true);
  toast('批量创建中…');
  const out = await api('/spaces/bulk', { method: 'POST', body: JSON.stringify({ urls }) });
  const ok = out.filter(x => x.id).length;
  toast(`完成：成功 ${ok} / ${out.length}`, ok === 0);
  $('#bulk-urls').value = ''; await loadSpaces();
}, '批量创建失败');

// ---------------------------------------------------------------- 节点
let nodeCache = [];
async function loadNodes() {
  const p = new URLSearchParams();
  if ($('#f-space').value) p.set('space_id', $('#f-space').value);
  if ($('#f-state').value) p.set('state', $('#f-state').value);
  if ($('#f-q').value.trim()) p.set('q', $('#f-q').value.trim());
  nodeCache = await api('/nodes?' + p);
  $('#node-count').textContent = `共 ${nodeCache.length} 个`;
  const spaces = Object.fromEntries((await api('/spaces')).map(s => [s.id, s.name]));
  const tb = $('#node-table tbody');
  tb.innerHTML = nodeCache.length ? nodeCache.map(n => `<tr>
    <td><input type="checkbox" class="chk-node" value="${n.id}"></td>
    <td class="mono" style="font-size:12px">#${n.space_id} ${esc(spaces[n.space_id] || '')}</td>
    <td title="${esc(n.deletion_reason || '')}">${esc(n.name)}</td>
    <td class="mono" style="font-size:12px">${esc(n.protocol)}</td>
    <td class="mono" style="font-size:12px">${esc(n.host)}:${n.port}</td>
    <td><span class="st ${n.state}">${({ healthy: '健康', unknown: '未探测', cooling: '探测失败', deleted: '已删除' })[n.state] || n.state}</span></td>
    <td class="mono">${n.delay_ms == null ? '—' : n.delay_ms + 'ms'}</td>
    <td class="mono" style="font-size:12px">${esc(n.exit_ip || '—')}</td>
    <td class="mono">${n.fail_count}</td>
    <td style="white-space:nowrap">
      <button class="tiny ghost" data-nact="probe" data-nid="${n.id}">探测</button>
      ${n.state === 'deleted'
        ? `<button class="tiny ghost" data-nact="revive" data-nid="${n.id}">复活</button>`
        : `<button class="tiny danger ghost" data-nact="delete" data-nid="${n.id}">删除</button>`}
    </td></tr>`).join('') : '<tr><td colspan="10" class="empty">没有匹配的节点</td></tr>';
}
$('#f-space').onchange = $('#f-state').onchange = loadNodes;
let qt; $('#f-q').oninput = () => { clearTimeout(qt); qt = setTimeout(loadNodes, 300); };
$('#node-table').addEventListener('click', async e => {
  const b = e.target.closest('button[data-nact]'); if (!b) return;
  const nid = +b.dataset.nid, act = b.dataset.nact;
  await guard(async () => {
    if (act === 'probe') { const r = await api(`/nodes/${nid}/probe`, { method: 'POST' }); toast(r.ok ? `可用 ${r.delay_ms}ms 出口 ${r.exit_ip || '?'}` : `不可用：${r.error}`, !r.ok); }
    if (act === 'delete') { await api(`/nodes/${nid}/delete`, { method: 'POST' }); toast('已从随机池移除'); }
    if (act === 'revive') { await api(`/nodes/${nid}/revive`, { method: 'POST' }); toast('已复活，等待下次探测'); }
    await loadNodes();
  });
});
$('#chk-all').onchange = e => $$('.chk-node').forEach(c => c.checked = e.target.checked);
async function bulk(action) {
  const ids = $$('.chk-node').filter(c => c.checked).map(c => +c.value);
  if (!ids.length) return toast('先勾选节点', true);
  await guard(async () => {
    toast(`正在${action === 'delete' ? '删除' : action === 'revive' ? '复活' : '探测'} ${ids.length} 个节点…`);
    await api('/nodes/bulk', { method: 'POST', body: JSON.stringify({ ids, action }) });
    toast('完成'); await loadNodes();
  });
}
$('#btn-bulk-delete').onclick = () => bulk('delete');
$('#btn-bulk-revive').onclick = () => bulk('revive');
$('#btn-probe-all').onclick = () => guard(async () => {
  toast('全量探测已启动，节点多时需要几分钟…');
  const r = await api('/probe/run', { method: 'POST' });
  const ok = r.reduce((a, x) => a + (x.ok || 0), 0), del = r.reduce((a, x) => a + (x.deleted || 0), 0);
  toast(`探测完成：可用 ${ok}，自动删除 ${del}`, false);
  await loadNodes();
}, '探测失败');

// ---------------------------------------------------------------- 日志
async function loadLogs() {
  const rows = await api('/logs?limit=200');
  const tb = $('#log-table tbody');
  tb.innerHTML = rows.length ? rows.map(r => `<tr>
    <td class="mono" style="font-size:12px">${fmtTime(r.ts)}</td>
    <td class="mono" style="font-size:12px">${esc(r.client || '')}</td>
    <td class="mono" style="font-size:12px">${esc(r.proto || '')}</td>
    <td class="mono" style="font-size:12px">${esc(r.target || '')}</td>
    <td>${esc(r.space_name || '—')}</td>
    <td>${esc(r.node_name || '—')}</td>
    <td><span class="st ${r.ok ? 'healthy' : 'deleted'}">${r.ok ? '成功' : '失败'}</span></td>
    <td class="mono" style="font-size:11.5px;color:var(--dim)">${esc(r.detail || '')}</td>
  </tr>`).join('') : '<tr><td colspan="8" class="empty">还没有连接记录</td></tr>';
}
$('#btn-log-refresh').onclick = loadLogs;

// ---------------------------------------------------------------- 设置
const SET_DEFS = {
  'set-probe': [
    ['probe_interval', '探测周期（秒）', '一轮全空间探测的间隔'],
    ['probe_timeout', '单节点超时（秒）'],
    ['probe_url', '探测目标 URL', '默认 generate_204'],
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
    ['filter_max_nodes_per_space', '每空间最多保留节点数（0=无限）'],
  ],
};
async function loadSettings() {
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
}
$('#btn-save-settings').onclick = () => guard(async () => {
  const payload = {};
  $$('input[data-key]').forEach(i => payload[i.dataset.key] = i.value);
  await api('/settings', { method: 'PUT', body: JSON.stringify(payload) });
  toast('设置已保存'); $('#save-msg').textContent = '已保存 ' + new Date().toLocaleTimeString('zh-CN', { hour12: false });
  setTimeout(() => $('#save-msg').textContent = '', 4000);
}, '保存失败');

// ---------------------------------------------------------------- 轮询
$('#btn-refresh-all').onclick = () => guard(async () => {
  toast('正在刷新所有空间的订阅…');
  const out = await api('/refresh-all', { method: 'POST' });
  const ok = out.filter(x => x.ok).length;
  toast(`完成：${ok}/${out.length} 个空间刷新成功`, ok === 0);
  loadTab($$('#tabs button.active')[0].dataset.tab);
}, '刷新失败');

loadOverview();
setInterval(async () => {
  const activeTab = $$('#tabs button.active')[0].dataset.tab;
  try {
    if (activeTab === 'overview') await loadOverview();
    else {
      const o = await api('/overview');
      $('#conn-badge').textContent = `活跃 ${o.proxy.active}`;
    }
  } catch { /* 静默 */ }
}, 5000);
