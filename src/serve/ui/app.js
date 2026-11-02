// The results page: reads the JSON API with the token the user pastes. Everything shown comes from
// the server (and partly from the scanned app), so the DOM is built with textContent only.
'use strict';

(function () {
  const TOKEN_KEY = 'bps.token';
  const REFRESH_MS = 30000;
  const MAX_ROWS = 500;
  const RISKS = ['high', 'medium', 'low', 'info', 'informational'];
  const STATES = ['queued', 'running', 'completed', 'incomplete', 'failed', 'cancelled', 'superseded',
    'passed', 'gate_failed', 'error'];

  const $ = (id) => document.getElementById(id);
  let token = loadToken();
  let target = null;
  let selected = null; // run id
  let timer = null;
  let generation = 0; // drops answers that arrive after the target or token changed
  const driftCache = new Map(); // run id -> drift, for runs that can't change any more

  // -- storage --------------------------------------------------------------------------------------

  function loadToken() {
    try { return sessionStorage.getItem(TOKEN_KEY) || ''; } catch (e) { return ''; }
  }

  function saveToken(t) {
    try {
      if (t) sessionStorage.setItem(TOKEN_KEY, t); else sessionStorage.removeItem(TOKEN_KEY);
    } catch (e) { /* the token then lives only in this page */ }
  }

  // -- DOM ------------------------------------------------------------------------------------------

  function el(tag, props, children) {
    const e = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (k === 'text') e.textContent = v;
      else if (k === 'className') e.className = v;
      else e.setAttribute(k, v);
    }
    for (const c of children || []) {
      if (c !== null && c !== undefined) e.append(c instanceof Node ? c : String(c));
    }
    return e;
  }

  function show(id, ...nodes) {
    const section = $(id);
    section.querySelector('.body').replaceChildren(...nodes);
    section.hidden = false;
  }

  function hideAll() {
    for (const id of ['summary', 'latest', 'runs', 'run']) $(id).hidden = true;
  }

  function tokenHint() {
    $('token').placeholder = token ? 'saved in this tab; paste another to switch' : 'bpt_...';
    $('token').required = !token;
  }

  function message(text) {
    const m = $('message');
    m.textContent = text || '';
    m.hidden = !text;
  }

  /// A definition list from [label, value] pairs; empty values are left out.
  function fields(pairs) {
    const dl = el('dl');
    for (const [k, v] of pairs) {
      if (v === null || v === undefined || v === '') continue;
      dl.append(el('dt', { text: k }), el('dd', {}, [v]));
    }
    return dl;
  }

  function badge(run) {
    const word = run.outcome || run.state || '?';
    const known = STATES.includes(word) ? ' state-' + word : '';
    return el('span', { className: 'badge' + known, text: word.replace('_', ' ') });
  }

  function riskCell(risk) {
    const r = String(risk || '').toLowerCase();
    return el('td', { className: RISKS.includes(r) ? 'risk risk-' + r : 'risk', text: risk || '' });
  }

  function time(s) {
    return s ? String(s).replace('T', ' ') : '';
  }

  function driftLine(d) {
    if (!d || typeof d !== 'object') return '';
    let line = `${d.new ?? 0} new, ${d.unchanged ?? 0} unchanged, ${d.fixed ?? 0} fixed`;
    if (d.since_job !== null && d.since_job !== undefined) line += ` (since job ${d.since_job})`;
    return line;
  }

  function gateLine(g) {
    if (!g || typeof g !== 'object') return '';
    const what = g.new_only ? 'new finding(s)' : 'finding(s)';
    return `${g.passed ? 'passed' : 'failed'}: ${g.count ?? 0} ${what} at or above ${g.fail_on}`;
  }

  /// Only http(s) links, never javascript: or data:.
  function pipelineLink(url) {
    if (typeof url !== 'string' || !/^https?:\/\//i.test(url)) return url || '';
    return el('a', { href: url, rel: 'noopener noreferrer', target: '_blank', text: url });
  }

  // -- the API --------------------------------------------------------------------------------------

  class ApiError extends Error {
    constructor(status, text) { super(text); this.status = status; }
  }

  async function request(path) {
    let resp;
    try {
      resp = await fetch(path, {
        headers: { Authorization: 'Bearer ' + token },
        cache: 'no-store',
        credentials: 'omit',
        redirect: 'error',
      });
    } catch (e) {
      throw new ApiError(0, 'the server can\'t be reached');
    }
    if (!resp.ok) {
      let text = resp.statusText;
      try { text = (await resp.json()).error.message || text; } catch (e) { /* not the envelope */ }
      throw new ApiError(resp.status, text);
    }
    return resp;
  }

  async function api(path) {
    const body = await (await request(path)).json();
    if (!body || body.ok !== true) throw new ApiError(500, 'unexpected answer');
    return body.data;
  }

  /// The answer, or null when the API says 404 (no completed run yet, no drift yet).
  async function maybe(path) {
    try { return await api(path); } catch (e) { if (e.status === 404) return null; throw e; }
  }

  function explain(e) {
    switch (e.status) {
      case 0: return 'Network error: ' + e.message + '.';
      case 401: return 'The token was refused: it is missing, unknown, expired or revoked.';
      case 403: return 'Not allowed with this token: ' + e.message + '.';
      case 429: return 'Too many requests: ' + e.message + '.';
      default: return 'Error' + (e.status ? ' ' + e.status : '') + ': ' + (e.message || e) + '.';
    }
  }

  /// Shows the error; a refused token is dropped, so a reload doesn't send it again.
  function fail(e) {
    if (e.status === 401) {
      token = '';
      saveToken('');
      stopTimer();
      tokenHint();
    }
    message(explain(e));
  }

  const enc = encodeURIComponent;
  const targetPath = () => '/v1/targets/' + enc(target);

  /// Fetches with the token and saves the file; the token never goes into a URL.
  async function download(path, name) {
    try {
      const bytes = await (await request(path)).arrayBuffer();
      // A neutral type: the browser saves the file and never renders it in this origin.
      const url = URL.createObjectURL(new Blob([bytes], { type: 'application/octet-stream' }));
      const a = el('a', { href: url, download: name });
      document.body.append(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (e) {
      fail(e);
    }
  }

  // -- views ----------------------------------------------------------------------------------------

  function renderSummary(t) {
    const gate = t.gate && t.gate.fail_on
      ? `fail on ${t.gate.fail_on}${t.gate.new_only ? ', new findings only' : ''}` : 'none';
    const counts = Object.entries(t.runs || {}).map(([k, n]) => `${k} ${n}`).join(', ') || 'none yet';
    show('summary', fields([
      ['Target', t.id],
      ['Base URL', t.base_url],
      ['Preset', t.preset],
      ['Gate', gate],
      ['Project', t.project_ready ? 'ready' : 'not uploaded yet'],
      ['Runs', counts],
    ]));
  }

  function runFields(r) {
    const reasons = Array.isArray(r.reasons) && r.reasons.length
      ? el('ul', {}, r.reasons.map((x) => el('li', { text: String(x) }))) : null;
    return fields([
      ['Run', r.run],
      ['State', badge(r)],
      ['Exit code', r.exit_code],
      ['Commit', r.commit],
      ['Ref', r.ref],
      ['Pipeline', pipelineLink(r.pipeline_url)],
      ['Preset', r.preset],
      ['Baseline', r.baseline ? 'yes (no gate)' : null],
      ['Queue position', r.position],
      ['Created', time(r.created)],
      ['Started', time(r.started)],
      ['Finished', time(r.finished)],
      ['Gate', gateLine(r.gate)],
      ['Drift', driftLine(r.drift)],
      ['Reasons', reasons],
    ]);
  }

  function renderRuns(runs) {
    if (!runs.length) { show('runs', el('p', { className: 'muted', text: 'No runs yet.' })); return; }
    const head = el('tr', {}, ['Run', 'State', 'Exit', 'Commit', 'Finished', 'Drift'].map((h) => el('th', { text: h })));
    const rows = runs.map((r) => {
      const pick = el('button', { type: 'button', className: 'link', text: r.run });
      pick.addEventListener('click', () => { selected = r.run; renderRuns(runs); renderRun(r); });
      const d = r.drift;
      return el('tr', r.run === selected ? { className: 'selected' } : {}, [
        el('td', {}, [pick]),
        el('td', {}, [badge(r)]),
        el('td', { text: r.exit_code ?? '' }),
        el('td', { className: 'mono', text: r.commit || '' }),
        el('td', { text: time(r.finished || r.started || r.created) }),
        el('td', { text: d ? `+${d.new ?? 0} / ${d.unchanged ?? 0} / -${d.fixed ?? 0}` : '' }),
      ]);
    });
    show('runs', el('div', { className: 'scroll' }, [el('table', {}, [el('thead', {}, [head]), el('tbody', {}, rows)])]),
      el('p', { className: 'muted', text: 'Drift: new / unchanged / fixed. Pick a run to see its drift.' }));
  }

  function findingsTable(title, list) {
    const items = Array.isArray(list) ? list : [];
    const parts = [el('h3', { text: `${title} (${items.length})` })];
    if (!items.length) { parts.push(el('p', { className: 'muted', text: 'None.' })); return parts; }
    const head = el('tr', {}, ['Risk', 'Name', 'Method', 'URL', 'Param'].map((h) => el('th', { text: h })));
    const rows = items.slice(0, MAX_ROWS).map((f) => el('tr', {}, [
      riskCell(f.risk),
      el('td', { text: f.name || f.alert_ref || '' }),
      el('td', { className: 'mono', text: f.method || '' }),
      el('td', { className: 'mono wrap', text: f.url || '' }),
      el('td', { className: 'mono', text: f.param || '' }),
    ]));
    parts.push(el('div', { className: 'scroll' }, [el('table', {}, [el('thead', {}, [head]), el('tbody', {}, rows)])]));
    if (items.length > MAX_ROWS) {
      parts.push(el('p', { className: 'muted', text: `${items.length - MAX_ROWS} more; download compare.json for all.` }));
    }
    return parts;
  }

  async function renderRun(r) {
    const gen = generation;
    const files = Object.entries((r.links && r.links.reports) || {})
      .filter(([, path]) => typeof path === 'string' && path.startsWith('/v1/'))
      .map(([kind]) => 'report.' + kind);
    const base = targetPath() + '/runs/' + enc(r.run);
    const buttons = el('div', { className: 'downloads' });
    const addButton = (file) => {
      const b = el('button', { type: 'button', text: 'Download ' + file });
      b.addEventListener('click', () => download(base + '/' + enc(file), `${target}-${r.run}-${file}`));
      buttons.append(b);
    };
    files.forEach(addButton);
    const drift = el('div', {}, [el('p', { className: 'muted', text: 'Loading the drift…' })]);
    $('run').querySelector('h2').textContent = 'Run ' + r.run;
    show('run', runFields(r), buttons, drift);

    let d = driftCache.get(r.run);
    try {
      if (d === undefined) d = await maybe(base + '/drift');
    } catch (e) {
      if (gen === generation) drift.replaceChildren(el('p', { className: 'error', text: explain(e) }));
      return;
    }
    if (gen !== generation || selected !== r.run) return;
    if (d && !['queued', 'running'].includes(d.state)) driftCache.set(r.run, d);
    if (!d || !d.compare) {
      drift.replaceChildren(el('p', { className: 'muted', text: 'This run has no drift (yet).' }));
      return;
    }
    addButton('compare.json');
    const warnings = Array.isArray(d.compare.warnings) && d.compare.warnings.length
      ? el('ul', { className: 'warnings' }, d.compare.warnings.map((w) => el('li', { text: 'Warning: ' + w }))) : null;
    drift.replaceChildren(...[
      el('p', { text: driftLine(d.compare.summary) }),
      warnings,
      ...findingsTable('New', d.compare.new),
      ...findingsTable('Fixed', d.compare.fixed),
    ].filter(Boolean));
  }

  // -- flow -----------------------------------------------------------------------------------------

  function stopTimer() {
    if (timer) clearTimeout(timer);
    timer = null;
  }

  async function refresh() {
    stopTimer();
    if (!token || !target) return;
    const gen = ++generation;
    $('status').textContent = 'Loading…';
    try {
      const [t, list, latest] = await Promise.all([
        api(targetPath()),
        api(targetPath() + '/runs?limit=20'),
        maybe(targetPath() + '/latest'),
      ]);
      if (gen !== generation) return;
      message('');
      const runs = list.runs || [];
      renderSummary(t);
      if (latest) show('latest', runFields(latest));
      else show('latest', el('p', { className: 'muted', text: 'No completed run yet.' }));
      if (!selected || !runs.some((r) => r.run === selected)) selected = latest ? latest.run : (runs[0] || {}).run;
      renderRuns(runs);
      const current = runs.find((r) => r.run === selected) || latest;
      if (current) renderRun(current); else $('run').hidden = true;
      const live = runs.some((r) => r.state === 'queued' || r.state === 'running');
      $('status').textContent = 'Updated ' + new Date().toLocaleTimeString() + (live ? '; refreshing every 30 s' : '');
      if (live) timer = setTimeout(refresh, REFRESH_MS);
    } catch (e) {
      if (gen !== generation) return;
      $('status').textContent = '';
      fail(e);
    }
  }

  async function connect() {
    stopTimer();
    const gen = ++generation;
    hideAll();
    $('picker').hidden = true;
    target = null;
    selected = null;
    driftCache.clear();
    tokenHint();
    if (!token) return;
    message('');
    try {
      const data = await api('/v1/targets');
      if (gen !== generation) return;
      const targets = (data.targets || []).map((t) => t.id).filter((id) => typeof id === 'string');
      if (!targets.length) { message('This token has no target.'); return; }
      $('target').replaceChildren(...targets.map((id) => el('option', { value: id, text: id })));
      $('picker').hidden = false;
      target = targets[0];
      await refresh();
    } catch (e) {
      if (gen === generation) fail(e);
    }
  }

  $('token-form').addEventListener('submit', (ev) => {
    ev.preventDefault();
    token = $('token').value.trim();
    $('token').value = '';
    saveToken(token);
    connect();
  });

  $('forget').addEventListener('click', () => {
    token = '';
    saveToken('');
    $('token').value = '';
    connect();
    message('The token is forgotten.');
  });

  $('target').addEventListener('change', () => {
    target = $('target').value;
    selected = null;
    driftCache.clear();
    hideAll();
    refresh();
  });

  $('refresh').addEventListener('click', refresh);

  connect();
})();
