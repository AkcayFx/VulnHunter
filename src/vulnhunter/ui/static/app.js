/* ═══════════════════════════════════════════════════════════════
   VulnHunter — Three-Panel Console
════════════════════════════════════════════════════════════════ */

const App = {
  token: localStorage.getItem('vh_token') || null,
  isGuest: false,
  ws: null,
  wsReady: false,
  scanning: false,
  activeFlowId: null,
  flows: [],
  term: null,
  fitAddon: null,
};

const Agents = {
  planner:  { status: 'idle', action: '' },
  recon:    { status: 'idle', action: '' },
  exploit:  { status: 'idle', action: '' },
  reporter: { status: 'idle', action: '' },
};

function $(id) { return document.getElementById(id); }
function esc(s) { if (!s) return ''; const d = document.createElement('div'); d.textContent = String(s); return d.innerHTML; }
function now() { return new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' }); }
function nowFull() { return new Date().toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' }); }
function fmtDur(s) { if (s == null) return '—'; const v = parseFloat(s); return v < 60 ? `${v.toFixed(0)}s` : `${Math.floor(v/60)}m ${Math.round(v%60)}s`; }
function riskCls(s) { return s >= 7 ? 'risk-high' : s >= 4 ? 'risk-medium' : 'risk-low'; }
function sevBadge(s) { const v = (s||'info').toLowerCase(); return `<span class="badge sev-${v}">${v.toUpperCase()}</span>`; }
function renderMd(t) {
  if (!t) return '';
  try {
    const raw = marked.parse(t, { breaks: true });
    const tmp = document.createElement('div');
    tmp.innerHTML = raw;
    tmp.querySelectorAll('script,iframe,object,embed,form').forEach(el => el.remove());
    tmp.querySelectorAll('[onload],[onerror],[onclick],[onmouseover]').forEach(el => {
      ['onload','onerror','onclick','onmouseover','onfocus','onblur'].forEach(a => el.removeAttribute(a));
    });
    tmp.querySelectorAll('a[href^="javascript:"]').forEach(el => el.removeAttribute('href'));
    return tmp.innerHTML;
  } catch { return esc(t).replace(/\n/g,'<br>'); }
}

function showToast(msg, type = 'info') {
  const c = $('toasts'), t = document.createElement('div');
  t.className = `toast ${type}`;
  t.innerHTML = `<div class="toast-dot"></div><span>${esc(msg)}</span>`;
  c.appendChild(t);
  setTimeout(() => { t.style.opacity='0'; t.style.transition='0.3s'; setTimeout(() => t.remove(), 300); }, 4000);
}

/* ═══════ AUTH ═══════ */
function showAuth() { $('auth-screen').style.display='flex'; $('shell').style.display='none'; }
function showApp() {
  $('auth-screen').style.display='none'; $('shell').style.display='flex';
  connectWS(); initTerminal(); renderAgents();
  if (!App.activeFlowId) newFlow();
}
function setAuthMsg(m,t='error') { const e=$('auth-msg'); e.textContent=m; e.className=`auth-msg ${t}`; }
function clearAuthMsg() { const e=$('auth-msg'); e.textContent=''; e.className='auth-msg'; e.style.display='none'; }

async function apiReq(path, opts={}) {
  const h = { 'Content-Type': 'application/json' };
  if (App.token) h['Authorization'] = `Bearer ${App.token}`;
  const r = await fetch(path, { ...opts, headers: { ...h, ...(opts.headers||{}) } });
  if (r.status === 401) { logout(); throw new Error('Unauthorized'); }
  if (!r.ok) { let m=`HTTP ${r.status}`; try { const d=await r.json(); m=d.detail||m; } catch {} throw new Error(m); }
  return r.status === 204 ? null : r.json();
}

async function handleLogin(e) {
  e.preventDefault();
  const email=$('li-email').value.trim(), pass=$('li-pass').value;
  if (!email||!pass) { setAuthMsg('Fill all fields'); return; }
  const btn=$('login-btn'); btn.disabled=true; btn.innerHTML='<div class="spinner"></div>'; clearAuthMsg();
  try { const d=await apiReq('/api/auth/login',{method:'POST',body:JSON.stringify({email,password:pass})}); App.token=d.access_token; localStorage.setItem('vh_token',App.token); App.isGuest=false; showApp(); }
  catch(err) { setAuthMsg(err.message.includes('500')?'Server error — try Guest':'Login failed: '+err.message); }
  finally { btn.disabled=false; btn.innerHTML='<span>Sign In</span>'; }
}

async function handleRegister(e) {
  e.preventDefault();
  const name=$('re-name').value.trim(), email=$('re-email').value.trim(), pass=$('re-pass').value;
  if (!email||!pass) { setAuthMsg('Email and password required'); return; }
  const btn=$('reg-btn'); btn.disabled=true; clearAuthMsg();
  try { const d=await apiReq('/api/auth/register',{method:'POST',body:JSON.stringify({email,password:pass,display_name:name})}); App.token=d.access_token; localStorage.setItem('vh_token',App.token); showApp(); }
  catch(err) { setAuthMsg('Registration failed: '+err.message); }
  finally { btn.disabled=false; }
}

function handleGuest() { App.token=null; App.isGuest=true; localStorage.removeItem('vh_token'); $('pl-user-name').textContent='Guest'; $('pl-user-email').textContent='guest@vulnhunter'; $('pl-avatar').textContent='G'; showApp(); }
function logout() { App.token=null; App.isGuest=false; localStorage.removeItem('vh_token'); if(App.ws){App.ws.onclose=null;App.ws.close();} showAuth(); }

/* ═══════ WEBSOCKET ═══════ */
function connectWS() {
  const p = location.protocol==='https:'?'wss:':'ws:';
  const url = App.token ? `${p}//${location.host}/ws?token=${encodeURIComponent(App.token)}` : `${p}//${location.host}/ws`;
  App.ws = new WebSocket(url);
  App.ws.onopen = () => { App.wsReady=true; $('ws-dot').className='ws-dot connected'; };
  App.ws.onmessage = (e) => { try { handleWS(JSON.parse(e.data)); } catch {} };
  App.ws.onclose = () => { App.wsReady=false; $('ws-dot').className='ws-dot'; setTimeout(connectWS,3000); };
}
function sendWS(d) { if(App.ws?.readyState===WebSocket.OPEN) App.ws.send(JSON.stringify(d)); }

/* ═══════ WS HANDLING ═══════ */
function handleWS(msg) {
  switch(msg.type) {
    case 'scan_started': onScanStart(msg); break;
    case 'agent_action': onAction(msg); break;
    case 'phase_change': onPhase(msg); break;
    case 'scan_complete': onComplete(msg); break;
    case 'scan_error': onError(msg); break;
    case 'error': addMsg('sys','Error',msg.message,'error'); break;
  }
}

function onScanStart(msg) {
  App.scanning = true;
  $('ws-dot').className = 'ws-dot scanning';
  showStatusBar(true);
  Object.keys(Agents).forEach(k => { Agents[k]={status:'idle',action:''}; });
  renderAgents(); updateFlowStatus('running');
  addMsg('sys','VulnHunter', `Scan initiated for **${esc(msg.target)}**\n\nPlanning attack strategy...`, 'thinking');
  tw(`\x1b[1;35m► Scan started: ${msg.target}\x1b[0m\r\n`);
}

function onAction(msg) {
  const k = agentKey(msg.agent);
  if (k && Agents[k]?.status !== 'done') { Agents[k].status='active'; Agents[k].action=msg.tool_name||msg.thought?.substring(0,50)||''; renderAgents(); }

  if (msg.action_type === 'tool_call') {
    const detail = msg.tool_input ? JSON.stringify(msg.tool_input).substring(0,300) : '';
    addMsgTool(msg.tool_name, `Calling **${esc(msg.tool_name)}**`, detail);
    tw(`\x1b[34m/work $ ${msg.tool_name}\x1b[0m ${(JSON.stringify(msg.tool_input)||'').substring(0,120)}\r\n`);
    addSearch(msg.tool_name, msg.tool_input);
  } else if (msg.action_type === 'tool_result') {
    const out = msg.tool_output || '';
    tw(`\x1b[32m${out.substring(0,300)}\x1b[0m\r\n\r\n`);
  } else if (msg.action_type === 'thinking') {
    addMsg('sys','VulnHunter', msg.thought?.substring(0,500) || '', 'thinking');
    tw(`\x1b[33m${(msg.thought||'').substring(0,200)}\x1b[0m\r\n`);
  }
}

function onPhase(msg) {
  const labels = { init:'Initializing', recon:'Reconnaissance', analysis:'Analysis', reporting:'Reporting', done:'Complete' };
  tw(`\r\n\x1b[1;36m═══ ${labels[msg.phase]||msg.phase} ═══\x1b[0m\r\n\r\n`);

  const map = { init:'planner', recon:'recon', analysis:'exploit', reporting:'reporter' };
  const order = ['init','recon','analysis','reporting','done'];
  const idx = order.indexOf(msg.phase);
  order.forEach((p,i) => { const k=map[p]; if(!k)return; if(i<idx) Agents[k].status='done'; else if(i===idx&&Agents[k].status!=='done') Agents[k].status='active'; });
  renderAgents(); updateTasks(msg.phase);
}

function onComplete(msg) {
  App.scanning = false;
  $('ws-dot').className = 'ws-dot connected';
  showStatusBar(false);
  Object.keys(Agents).forEach(k => { Agents[k].status='done'; Agents[k].action=''; }); renderAgents();

  const flow = activeFlow();
  if (flow) { flow.status='done'; flow.report=msg; renderFlows(); }

  const vc = msg.total_vulns||0, rs = (msg.risk_score||0).toFixed(1), cc = (msg.attack_chains||[]).length;

  let card = `<div class="msg-result-card"><div class="msg-result-stats">`;
  card += `<div class="msg-stat"><div class="msg-stat-value ${riskCls(msg.risk_score)}">${rs}</div><div class="msg-stat-label">Risk Score</div></div>`;
  card += `<div class="msg-stat"><div class="msg-stat-value">${vc}</div><div class="msg-stat-label">Vulns</div></div>`;
  card += `<div class="msg-stat"><div class="msg-stat-value">${cc}</div><div class="msg-stat-label">Chains</div></div>`;
  card += `<div class="msg-stat"><div class="msg-stat-value">${fmtDur(msg.duration)}</div><div class="msg-stat-label">Duration</div></div>`;
  card += `</div>`;
  if (msg.vulnerabilities?.length) {
    msg.vulnerabilities.slice(0,8).forEach(v => { card += `<div style="display:flex;align-items:center;gap:6px;padding:3px 0">${sevBadge(v.severity)}<span style="font-size:0.82rem;color:var(--t1)">${esc(v.title)}</span></div>`; });
    if (msg.vulnerabilities.length > 8) card += `<div style="color:var(--t4);font-size:0.78rem;margin-top:4px">+ ${msg.vulnerabilities.length-8} more findings</div>`;
  }
  card += `</div>`;

  addMsgRaw('sys','VulnHunter', msg.summary || `Scan complete. ${vc} vulnerabilities found.`, card, 'result');
  tw(`\r\n\x1b[1;32m═══ Scan Complete ═══\x1b[0m\r\nRisk: ${rs}/10 | Vulns: ${vc} | Chains: ${cc}\r\n`);
  showToast(`Scan complete — Risk ${rs}/10`, msg.risk_score>=7?'error':msg.risk_score>=4?'warning':'success');
  if (msg.phase !== 'done') updateTasks('done');
}

function onError(msg) {
  App.scanning = false;
  $('ws-dot').className = 'ws-dot connected';
  showStatusBar(false); updateFlowStatus('error');
  addMsg('sys','VulnHunter', `Scan failed: ${msg.message||'Unknown error'}`, 'error');
  tw(`\x1b[1;31m✗ FAILED: ${msg.message||''}\x1b[0m\r\n`);
  showToast('Scan failed: '+(msg.message||''), 'error');
}

/* ═══════ STATUS BAR ═══════ */
function showStatusBar(show) { $('statusbar').classList.toggle('active', show); }

/* ═══════ FLOWS ═══════ */
function newFlow() {
  const f = { id: `f-${Date.now()}`, name:'New Scan', target:'', status:'idle', time:new Date().toISOString(), messages:[], tasks:[], searches:[], report:null };
  App.flows.unshift(f); App.activeFlowId = f.id;
  renderFlows(); clearChat(); resetAgents(); clearTasks(); clearSearches();
  addMsg('sys','VulnHunter','Enter a target domain, IP, or URL to begin scanning.\n\nExample: `scanme.nmap.org`', null);
  $('pc-flow-name').textContent = 'New Scan';
}

function selectFlow(id) {
  App.activeFlowId = id; renderFlows();
  const f = activeFlow(); if (!f) return;
  clearChat();
  f.messages.forEach(m => renderMsg(m));
  $('pc-flow-name').textContent = f.name||'New Scan';
  renderTasksFor(f);
}

function activeFlow() { return App.flows.find(f => f.id === App.activeFlowId); }
function updateFlowStatus(s) { const f=activeFlow(); if(f){f.status=s; renderFlows();} }

function renderFlows() {
  const el = $('flow-list'); if (!el) return;
  el.innerHTML = App.flows.map(f => {
    const act = f.id===App.activeFlowId ? 'active' : '';
    let icon = '', cls = '';
    if (f.status==='running') { icon='⚡'; cls='running'; }
    else if (f.status==='done') { icon='✓'; cls='done'; }
    else if (f.status==='error') { icon='✗'; cls='error'; }
    return `<div class="flow-item ${act}" onclick="selectFlow('${f.id}')">
      <span class="flow-name">${esc(f.name)}</span>
      ${icon ? `<span class="flow-status-icon ${cls}">${icon}</span>` : ''}
      <button class="flow-dots" onclick="event.stopPropagation()">···</button>
    </div>`;
  }).join('');
}

/* ═══════ CHAT ═══════ */
function clearChat() { $('chat-messages').innerHTML = ''; }

function addMsg(role, sender, content, badge) {
  const m = { role, sender, content, badge, time: now() };
  const f = activeFlow(); if (f) f.messages.push(m);
  renderMsg(m);
}

function addMsgTool(toolName, content, detail) {
  const m = { role:'tool', sender:toolName||'Tool', content, badge:'tool-call', time:now(), detail };
  const f = activeFlow(); if (f) f.messages.push(m);
  renderMsg(m);
}

function addMsgRaw(role, sender, content, extraHtml, badge) {
  const m = { role, sender, content, badge, extraHtml, time:now() };
  const f = activeFlow(); if (f) f.messages.push(m);
  renderMsg(m);
}

function renderMsg(m) {
  const el = $('chat-messages'); if (!el) return;
  const isUser = m.role === 'user';
  const isTool = m.role === 'tool';

  const iconCls = isUser ? 'usr' : isTool ? 'tool' : 'sys';
  const iconText = isUser ? 'A' : isTool ? '⚙' : '◆';

  let badgeIcon = '';
  if (m.badge === 'thinking') badgeIcon = `<span class="msg-badge-icon thinking"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 8v4l3 3"/></svg> Show thinking</span>`;
  else if (m.badge === 'tool-call') badgeIcon = `<span class="msg-badge-icon tool-call"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14.7 6.3a1 1 0 000 1.4l1.6 1.6a1 1 0 001.4 0l3.77-3.77a6 6 0 01-7.94 7.94l-6.91 6.91a2.12 2.12 0 01-3-3l6.91-6.91a6 6 0 017.94-7.94l-3.76 3.76z"/></svg> Tool call</span>`;
  else if (m.badge === 'result') badgeIcon = `<span class="msg-badge-icon result"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><path d="M22 4L12 14.01l-3-3"/></svg> Result</span>`;
  else if (m.badge === 'error') badgeIcon = `<span class="msg-badge-icon error"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/></svg> Error</span>`;

  const detailId = m.detail ? `det-${Date.now()}-${Math.random().toString(36).substr(2,5)}` : '';
  const detailHtml = m.detail ? `<span class="msg-show-details" onclick="document.getElementById('${detailId}').classList.toggle('open')">Show details</span><div class="msg-details" id="${detailId}">${esc(m.detail)}</div>` : '';

  const div = document.createElement('div');
  div.className = `msg ${isUser ? 'msg-user' : ''}`;
  div.innerHTML = `
    <div class="msg-icon ${iconCls}">${iconText}</div>
    <div class="msg-body">
      <div class="msg-bubble">
        ${badgeIcon ? `<div class="msg-bubble-header">${badgeIcon}</div>` : ''}
        <div class="msg-text">${renderMd(m.content||'')}</div>
        ${detailHtml}
        ${m.extraHtml||''}
        <div class="msg-footer">
          <span class="msg-time">${m.time||''}</span>
          ${!isUser ? `<div class="msg-actions">
            <button class="msg-action-btn" title="Like"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M14 9V5a3 3 0 00-3-3l-4 9v11h11.28a2 2 0 002-1.7l1.38-9a2 2 0 00-2-2.3H14z"/></svg></button>
            <button class="msg-action-btn" title="Dislike"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10 15V19a3 3 0 003 3l4-9V2H5.72a2 2 0 00-2 1.7l-1.38 9a2 2 0 002 2.3H10z"/></svg></button>
            <button class="msg-action-btn" title="Regenerate"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M23 4v6h-6"/><path d="M1 20v-6h6"/><path d="M3.51 9a9 9 0 0114.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0020.49 15"/></svg></button>
            <button class="msg-action-btn" title="Comment"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 11.5a8.38 8.38 0 01-.9 3.8 8.5 8.5 0 01-7.6 4.7 8.38 8.38 0 01-3.8-.9L3 21l1.9-5.7a8.38 8.38 0 01-.9-3.8 8.5 8.5 0 014.7-7.6 8.38 8.38 0 013.8-.9h.5a8.48 8.48 0 018 8v.5z"/></svg></button>
            <button class="msg-action-btn" title="Share"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/><line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/></svg></button>
          </div>` : ''}
        </div>
      </div>
    </div>`;
  el.appendChild(div);
  el.scrollTop = el.scrollHeight;
}

function sendChat() {
  const inp = $('chat-input'), text = inp.value.trim();
  if (!text) return;
  inp.value = ''; autoResize(inp);
  addMsg('user', 'You', text, null);

  const justTarget = text.match(/^(?:scan\s+)?([a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}(?::\d+)?(?:\/\S*)?|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)$/i);
  const taskWithTarget = text.match(/^(.+?)\s+(?:on|for|against|at)\s+([a-zA-Z0-9][\w.-]*\.[a-zA-Z]{2,}(?::\d+)?(?:\/\S*)?|(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?)\s*$/i);
  const scanCmd = text.match(/^scan\s+(\S+)(?:\s+(.+))?/i);

  if (justTarget) {
    startScan(justTarget[1].trim(), '');
  } else if (taskWithTarget) {
    startScan(taskWithTarget[2].trim(), taskWithTarget[1].trim());
  } else if (scanCmd) {
    startScan(scanCmd[1].trim(), (scanCmd[2] || '').trim());
  } else {
    addMsg('sys','VulnHunter',
      '**Commands:**\n' +
      '- `example.com` — Full scan\n' +
      '- `test SQL injection on example.com` — Focused task\n' +
      '- `check CORS on api.example.com` — Specific test\n' +
      '- `scan example.com find XSS` — Scan with instructions', null);
  }
}

function startScan(target, task) {
  if (!App.wsReady) { showToast('Not connected','warning'); return; }
  if (App.scanning) { showToast('Scan already running','warning'); return; }
  const label = task ? `${task} → ${target}` : target;
  const f = activeFlow();
  if (f) { f.name=label; f.target=target; f.status='running'; f.time=new Date().toISOString(); renderFlows(); $('pc-flow-name').textContent=label; }
  buildTasks(target);
  sendWS({ type:'start_scan', target, task: task || '' });
}

/* ═══════ TERMINAL ═══════ */
function initTerminal() {
  if (App.term) return;
  const c = $('xterm-container');
  if (!c || typeof Terminal === 'undefined') return;

  App.term = new Terminal({
    theme: { background:'#0a0a0a', foreground:'#999999', cursor:'#dc2626', selectionBackground:'rgba(220,38,38,0.25)',
      black:'#111111', red:'#ef4444', green:'#22c55e', yellow:'#f59e0b', blue:'#60a5fa', magenta:'#dc2626', cyan:'#06b6d4', white:'#f0f0f0',
      brightBlack:'#555555', brightRed:'#fca5a5', brightGreen:'#86efac', brightYellow:'#fcd34d', brightBlue:'#93c5fd', brightMagenta:'#ff6b6b', brightCyan:'#67e8f9', brightWhite:'#ffffff' },
    fontFamily: "'JetBrains Mono', monospace", fontSize: 13, lineHeight: 1.35,
    cursorBlink: false, disableStdin: true, scrollback: 5000, convertEol: true,
  });
  if (typeof FitAddon !== 'undefined') { App.fitAddon = new FitAddon.FitAddon(); App.term.loadAddon(App.fitAddon); }
  App.term.open(c);
  if (App.fitAddon) App.fitAddon.fit();

  App.term.writeln('\x1b[2m Awaiting scan commands...\x1b[0m');
  App.term.writeln('');
  new ResizeObserver(() => { if (App.fitAddon) App.fitAddon.fit(); }).observe(c);
}

function tw(t) { if (App.term) App.term.write(t); }

/* ═══════ TASKS ═══════ */
function buildTasks(target) {
  const f = activeFlow(); if (!f) return;
  f.tasks = [
    { name:`Scan ${target}`, status:'running', detail:'' },
    { name:'Initial reconnaissance and connectivity verification', status:'pending', detail:'' },
    { name:'Port scanning and service enumeration', status:'pending', detail:'' },
    { name:'Technology fingerprinting and version detection', status:'pending', detail:'' },
    { name:'Web vulnerability analysis and exploitation', status:'pending', detail:'' },
    { name:'Attack chain analysis and MITRE mapping', status:'pending', detail:'' },
    { name:'Compile final vulnerability report', status:'pending', detail:'' },
  ];
  renderTasks();
}

function updateTasks(phase) {
  const f = activeFlow(); if (!f?.tasks?.length) return;
  const map = { recon:2, analysis:4, reporting:6, done:f.tasks.length };
  const upTo = map[phase]||0;
  f.tasks.forEach((t,i) => { if(i<upTo) t.status='completed'; else if(i===upTo) t.status='running'; });
  if (phase==='done') f.tasks.forEach(t => t.status='completed');
  renderTasks();
}

function clearTasks() { $('tasks-list').innerHTML='<div class="pr-empty"><p>No tasks yet</p><span class="pr-empty-sub">Start a scan to see progress</span></div>'; }

function renderTasks() {
  const f = activeFlow(), el = $('tasks-list');
  if (!el || !f?.tasks?.length) return;
  el.innerHTML = f.tasks.map(t => `
    <div class="task-item" onclick="this.classList.toggle('expanded')">
      <div class="task-icon ${t.status}"></div>
      <div class="task-body">
        <div class="task-name">${esc(t.name)}</div>
        <div class="task-show">Show details</div>
        <div class="task-detail">${esc(t.detail||'No additional details')}</div>
      </div>
    </div>`).join('');
}

function renderTasksFor(f) { if(f?.tasks?.length) renderTasks(); else clearTasks(); }

/* ═══════ AGENTS ═══════ */
const AGENTS = [
  { key:'planner', emoji:'🧠', name:'Task Planner' },
  { key:'recon',   emoji:'🔍', name:'Recon Agent' },
  { key:'exploit', emoji:'⚡', name:'Exploit Agent' },
  { key:'reporter',emoji:'📋', name:'Reporter Agent' },
];

function resetAgents() { Object.keys(Agents).forEach(k => { Agents[k]={status:'idle',action:''}; }); renderAgents(); }

function renderAgents() {
  const el = $('agents-list'); if (!el) return;
  el.innerHTML = AGENTS.map(a => {
    const s = Agents[a.key]||{status:'idle',action:''};
    return `<div class="agent-card ${s.status}">
      <div class="agent-top"><div class="agent-emoji">${a.emoji}</div><span class="agent-name">${a.name}</span><span class="agent-badge ${s.status}">${s.status}</span></div>
      <div class="agent-action">${esc(s.action)||'Waiting...'}</div>
    </div>`;
  }).join('');
}

function agentKey(n) { const s=(n||'').toLowerCase(); if(s.includes('plan')||s.includes('orch'))return'planner'; if(s.includes('recon'))return'recon'; if(s.includes('exploit'))return'exploit'; if(s.includes('report'))return'reporter'; return null; }

/* ═══════ SEARCHES ═══════ */
function addSearch(tool, input) {
  const f = activeFlow(); if (!f) return;
  const q = typeof input==='object' ? JSON.stringify(input).substring(0,120) : String(input||'').substring(0,120);
  f.searches.unshift({ tool:tool||'Unknown', query:q, time:nowFull() });
  renderSearches();
}

function clearSearches() { $('searches-list').innerHTML='<div class="pr-empty"><p>No search queries yet</p></div>'; }

function renderSearches() {
  const f = activeFlow(), el = $('searches-list');
  if (!el || !f?.searches?.length) return;
  el.innerHTML = f.searches.slice(0,60).map(s => `
    <div class="search-item">
      <div class="search-dot"></div>
      <div class="search-body"><div class="search-tool">${esc(s.tool)}</div><div class="search-query">${esc(s.query)}</div></div>
      <span class="search-time">${s.time}</span>
    </div>`).join('');
}

/* ═══════ TABS ═══════ */
function switchRTab(t) {
  document.querySelectorAll('.pr-tab').forEach(b => b.classList.toggle('active', b.dataset.rtab===t));
  document.querySelectorAll('.pr-pane').forEach(p => p.classList.toggle('active', p.dataset.rpane===t));
  if (t==='terminal' && App.fitAddon) setTimeout(() => App.fitAddon.fit(), 50);
}

function autoResize(el) { el.style.height='auto'; el.style.height=Math.min(el.scrollHeight,100)+'px'; }

/* ═══════ INIT ═══════ */
function init() {
  document.querySelectorAll('.tab').forEach(t => t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(b => b.classList.toggle('active', b===t));
    $('login-form').style.display = t.dataset.tab==='login'?'flex':'none';
    $('reg-form').style.display = t.dataset.tab==='register'?'flex':'none';
    clearAuthMsg();
  }));

  $('login-form')?.addEventListener('submit', handleLogin);
  $('reg-form')?.addEventListener('submit', handleRegister);
  $('guest-btn')?.addEventListener('click', handleGuest);
  $('logout-btn')?.addEventListener('click', logout);
  $('new-flow-btn')?.addEventListener('click', newFlow);
  $('chat-send')?.addEventListener('click', sendChat);
  $('stop-btn')?.addEventListener('click', () => { sendWS({type:'cancel_scan'}); showToast('Cancelling...','warning'); });
  $('settings-btn')?.addEventListener('click', logout);

  const ci = $('chat-input');
  if (ci) {
    ci.addEventListener('keydown', e => { if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();sendChat();} });
    ci.addEventListener('input', () => autoResize(ci));
  }

  document.querySelectorAll('.pr-tab').forEach(t => t.addEventListener('click', () => switchRTab(t.dataset.rtab)));
  document.querySelectorAll('.pc-tab').forEach(t => t.addEventListener('click', () => {
    document.querySelectorAll('.pc-tab').forEach(b => b.classList.toggle('active',b===t));
  }));

  $('pc-menu-btn')?.addEventListener('click', () => $('panel-left').classList.toggle('mobile-open'));
  $('pc-toggle-right')?.addEventListener('click', () => $('panel-right').classList.toggle('collapsed'));

  if (App.token) showApp(); else showAuth();
}

init();
