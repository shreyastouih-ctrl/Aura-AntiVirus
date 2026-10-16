const { invoke } = window.__TAURI__.core;
const { listen } = window.__TAURI__.event;

const $ = (id) => document.getElementById(id);
const status = $('status');
const results = $('results');
const progressBar = $('progressBar');
const progressFill = $('progressFill');

let totalFiles = 0;

const verdictClass = (v) =>
  v === 'Malicious' ? 'malicious' : v === 'Suspicious' ? 'suspicious' : 'clean';

function renderThreats(threats) {
  if (!threats || threats.length === 0) {
    results.innerHTML = '<span class="clean">No threats found.</span>';
    return;
  }
  const rows = threats
    .map(
      (t) => `<tr>
        <td class="${verdictClass(t.verdict)}">${t.verdict}<br><span class="muted">${(t.confidence * 100).toFixed(0)}%</span></td>
        <td>${t.path}<br><span class="muted">${t.kind}</span></td>
        <td>${(t.reasons || []).map((r) => `<div>${r}</div>`).join('')}</td>
      </tr>`
    )
    .join('');
  results.innerHTML = `<table><thead><tr><th>Verdict</th><th>File</th><th>Reasons</th></tr></thead><tbody>${rows}</tbody></table>`;
}

async function runScan(command) {
  status.textContent = 'Starting scan...';
  progressBar.style.display = 'block';
  progressFill.style.width = '0%';
  results.innerHTML = '';
  ['quickScan', 'fullScan', 'scanDrives'].forEach((id) => ($(id).disabled = true));
  try {
    const threats = await invoke(command);
    renderThreats(threats);
    status.innerHTML = `<strong>Scan complete</strong> — ${threats.length} threat(s) found.`;
  } catch (e) {
    status.textContent = 'Error: ' + e;
  } finally {
    ['quickScan', 'fullScan', 'scanDrives'].forEach((id) => ($(id).disabled = false));
  }
}

$('quickScan').addEventListener('click', () => runScan('quick_scan'));
$('fullScan').addEventListener('click', () => runScan('full_scan'));
$('scanDrives').addEventListener('click', () => runScan('scan_drives'));

$('sensitivity').addEventListener('change', async (ev) => {
  try {
    const config = await invoke('get_config');
    config.heuristic_sensitivity = ev.target.value.replace(/^./, (c) => c.toUpperCase());
    await invoke('set_config', { config });
  } catch (e) {
    status.textContent = 'Error: ' + e;
  }
});

async function loadQuarantine() {
  try {
    const entries = await invoke('quarantine_list');
    if (entries.length === 0) {
      $('quarantine').innerHTML = '<span class="muted">Quarantine is empty.</span>';
      return;
    }
    const rows = entries
      .map(
        (e) => `<tr>
          <td>${e.original_path}</td>
          <td>${e.reason}</td>
          <td>${new Date(e.quarantined_at).toLocaleString()}</td>
          <td>
            <button class="btn btn-secondary" data-restore="${e.id}">Restore</button>
            <button class="btn btn-secondary" data-delete="${e.id}">Delete</button>
          </td>
        </tr>`
      )
      .join('');
    $('quarantine').innerHTML = `<table><thead><tr><th>File</th><th>Reason</th><th>Quarantined</th><th></th></tr></thead><tbody>${rows}</tbody></table>`;
  } catch (e) {
    $('quarantine').textContent = 'Error: ' + e;
  }
}

$('quarantine').addEventListener('click', async (ev) => {
  const restore = ev.target.getAttribute('data-restore');
  const del = ev.target.getAttribute('data-delete');
  try {
    if (restore) await invoke('quarantine_restore', { id: restore });
    if (del) await invoke('quarantine_delete', { id: del });
    loadQuarantine();
  } catch (e) {
    status.textContent = 'Error: ' + e;
  }
});

async function loadHistory(threatsOnly) {
  try {
    const rows = await invoke('history', { limit: 100, threatsOnly });
    if (rows.length === 0) {
      $('history').innerHTML = '<span class="muted">No history recorded yet.</span>';
      return;
    }
    const trs = rows
      .map(
        (r) => `<tr>
          <td class="${verdictClass(r.verdict)}">${r.verdict}</td>
          <td>${r.file_path}</td>
          <td>${new Date(r.scanned_at).toLocaleString()}</td>
        </tr>`
      )
      .join('');
    $('history').innerHTML = `<table><thead><tr><th>Verdict</th><th>File</th><th>When</th></tr></thead><tbody>${trs}</tbody></table>`;
  } catch (e) {
    $('history').textContent = 'Error: ' + e;
  }
}

$('refreshQuarantine').addEventListener('click', loadQuarantine);
$('historyThreats').addEventListener('click', () => loadHistory(true));
$('historyAll').addEventListener('click', () => loadHistory(false));

$('monitorToggle').addEventListener('click', async () => {
  try {
    await invoke('start_monitor');
    $('monitorToggle').textContent = 'Real-time: On';
    status.textContent = 'Real-time protection active on common folders.';
  } catch (e) {
    status.textContent = 'Error: ' + e;
  }
});

listen('scan-progress', (event) => {
  const p = event.payload;
  totalFiles = p.files_total || totalFiles;
  const pct = totalFiles > 0 ? (p.files_scanned / totalFiles) * 100 : 0;
  progressFill.style.width = Math.min(pct, 100) + '%';
  status.innerHTML = `Scanning: ${p.files_scanned}/${totalFiles}<br>Threats: <span class="threats">${p.threats_found}</span><br><small class="muted">${p.current_path || ''}</small>`;
});

listen('scan-complete', (event) => {
  progressBar.style.display = 'none';
  status.innerHTML = `<strong>Scan complete</strong> — ${event.payload} threat(s) found.`;
});

listen('monitor-threat', (event) => {
  const t = event.payload;
  status.innerHTML = `<span class="${verdictClass(t.verdict)}">${t.verdict}</span> — ${t.path}<br><small class="muted">${t.summary}</small>`;
});

loadQuarantine();
