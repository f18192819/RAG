const $ = (selector) => document.querySelector(selector);
const state = { session: null, csrf: '', assignments: [], assignment: null, sort: 'balanced_score', timer: null, loginRole: 'student' };

async function api(path, options = {}) {
  const headers = { ...(options.headers || {}) };
  if (state.csrf && !['GET', 'HEAD'].includes((options.method || 'GET').toUpperCase())) headers['X-CSRF-Token'] = state.csrf;
  if (options.body && !(options.body instanceof FormData)) headers['Content-Type'] = 'application/json';
  const response = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  let body = null;
  const type = response.headers.get('content-type') || '';
  if (type.includes('json')) body = await response.json();
  if (!response.ok) throw new Error(body?.detail || `请求失败 (${response.status})`);
  return body;
}

function toast(message) {
  const node = $('#toast'); node.textContent = message; node.classList.add('show');
  clearTimeout(node._timer); node._timer = setTimeout(() => node.classList.remove('show'), 2600);
}

function setView(authenticated) {
  $('#login-view').classList.toggle('hidden', authenticated);
  $('#dashboard-view').classList.toggle('hidden', !authenticated);
}

function percent(value) { return value == null ? '—' : `${(Number(value) * 100).toFixed(2)}%`; }
function timeText(value) { return value ? new Date(value).toLocaleString('zh-CN', { hour12: false }) : '—'; }

async function bootstrap() {
  try {
    state.session = await api('/api/auth/session'); state.csrf = state.session.csrf_token;
    showDashboard();
  } catch (_) { setView(false); }
}

function selectLoginRole(role) {
  state.loginRole = role;
  document.querySelectorAll('.login-tab').forEach(x => x.classList.toggle('active', x.dataset.loginRole === role));
  const admin = role === 'admin';
  $('#identity-label').textContent = admin ? '管理员账号' : '学号';
  $('#secret-label').textContent = admin ? '密码' : 'Token';
  $('#login-description').textContent = admin ? '管理作业开放状态并预览榜单' : '使用学号与个人 Token 登录';
  $('#identity').value = ''; $('#secret').value = ''; $('#login-error').textContent = '';
}

document.querySelectorAll('.login-tab').forEach(button => button.addEventListener('click', () => selectLoginRole(button.dataset.loginRole)));
$('#login-form').addEventListener('submit', async event => {
  event.preventDefault(); $('#login-error').textContent = '';
  const identity = $('#identity').value.trim(), secret = $('#secret').value;
  try {
    const admin = state.loginRole === 'admin';
    const payload = admin ? { username: identity, password: secret } : { student_id: identity, token: secret };
    const result = await api(admin ? '/api/auth/admin-login' : '/api/auth/student-login', { method: 'POST', body: JSON.stringify(payload) });
    state.session = result; state.csrf = result.csrf_token; $('#secret').value = ''; await showDashboard();
  } catch (error) { $('#login-error').textContent = error.message; }
});

async function showDashboard() {
  setView(true); $('#user-name').textContent = state.session.display_name; $('#role-badge').textContent = state.session.role === 'admin' ? '管理员' : '学生';
  const admin = state.session.role === 'admin';
  $('#admin-panel').classList.toggle('hidden', !admin); $('#upload-fab').classList.toggle('hidden', admin);
  await loadAssignments();
  clearInterval(state.timer); state.timer = setInterval(refreshAll, 10000);
}

async function loadAssignments() {
  state.assignments = await api('/api/assignments');
  if (!state.assignments.some(x => x.slug === state.assignment)) state.assignment = state.assignments[0]?.slug || null;
  renderAssignmentTabs(); renderAdminSwitches();
  if (state.assignment) await refreshAll(); else renderNoAssignments();
}

function renderAssignmentTabs() {
  const tabs = $('#assignment-tabs'); tabs.innerHTML = '';
  state.assignments.forEach(item => {
    const button = document.createElement('button'); button.className = `assignment-tab ${item.slug === state.assignment ? 'active' : ''}`;
    button.textContent = item.display_name + (item.status === 'closed' ? '（已截止）' : item.status === 'hidden' ? '（未开放）' : '');
    button.addEventListener('click', async () => { state.assignment = item.slug; renderAssignmentTabs(); syncUploadVisibility(); await refreshAll(); }); tabs.appendChild(button);
  });
  syncUploadVisibility();
}

function renderAdminSwitches() {
  const box = $('#admin-switches'); box.innerHTML = '';
  if (state.session.role !== 'admin') return;
  state.assignments.forEach(item => {
    const label = document.createElement('label'); label.className = 'assignment-status-control';
    const name = document.createElement('span'); name.textContent = item.display_name;
    const select = document.createElement('select');
    select.setAttribute('aria-label', `${item.display_name}状态`);
    for (const [value, text] of [['hidden', '未开放'], ['open', '开放'], ['closed', '已截止']]) {
      const option = document.createElement('option'); option.value = value; option.textContent = text; select.appendChild(option);
    }
    select.value = item.status;
    select.addEventListener('change', async () => {
      const previous = item.status;
      select.disabled = true;
      try { await api(`/api/admin/assignments/${item.slug}`, { method: 'PATCH', body: JSON.stringify({ status: select.value }) }); toast('作业状态已更新'); await loadAssignments(); }
      catch (error) { select.value = previous; toast(error.message); }
      finally { select.disabled = false; }
    });
    label.append(name, select); box.appendChild(label);
  });
}

function syncUploadVisibility() {
  const uploadButton = $('#upload-fab');
  const item = state.assignments.find(x => x.slug === state.assignment);
  const canSubmit = state.session?.role === 'student' && item?.status === 'open';
  uploadButton.classList.toggle('hidden', !canSubmit);
}

function renderNoAssignments() {
  $('#ranking-body').innerHTML = ''; $('#empty-state').classList.remove('hidden');
  $('#empty-state strong').textContent = '当前没有开放的作业'; $('#submission-status').classList.add('hidden'); $('#upload-fab').classList.add('hidden');
}

async function refreshAll() {
  if (!state.assignment) return;
  $('#refresh-icon').style.display = 'inline-block';
  try { await Promise.all([loadLeaderboard(), loadSubmission()]); }
  catch (error) { if (/登录/.test(error.message)) return forceLogin(); toast(error.message); }
}

async function loadLeaderboard() {
  const data = await api(`/api/assignments/${state.assignment}/leaderboard?sort=${state.sort}`);
  const body = $('#ranking-body'); body.innerHTML = '';
  const myRanking = $('#my-ranking');

  if (state.session.role === 'student' && data.my_rank) {
    myRanking.textContent = `我的排名：${rankLabel(data.my_rank)}`;
    myRanking.classList.remove('hidden');
  } else {
    myRanking.classList.add('hidden');
  }
  data.entries.forEach(entry => {
    const row = document.createElement('tr');
    if (entry.is_me) row.classList.add('is-me');
    const values = [
      `<span class="rank ${entry.rank <= 3 ? 'top' : ''}">${entry.rank <= 3 ? ['Ⅰ', 'Ⅱ', 'Ⅲ'][entry.rank - 1] : entry.rank}</span>`,
      escapeHtml(entry.display_name),
      `<span class="${state.sort === 'balanced_score' ? 'score-pill' : 'score-main'}">${percent(entry.balanced_score)}</span>`,
      `<span class="${state.sort === 'answer_accuracy' ? 'score-pill' : 'score-main'}">${percent(entry.answer_accuracy)}</span>`,
      `<span class="${state.sort === 'reject_recall' ? 'score-pill' : 'score-main'}">${percent(entry.reject_recall)}</span>`,
      timeText(entry.last_submitted_at),
    ];
    row.innerHTML = values.map(value => `<td>${value}</td>`).join(''); body.appendChild(row);
  });
  $('#empty-state').classList.toggle('hidden', data.entries.length > 0); $('#updated-at').textContent = `更新于 ${timeText(data.updated_at)}`;
}

function rankLabel(rank) {
  return String(rank);
}

async function loadSubmission() {
  if (state.session.role === 'admin') {
    $('#submission-status').classList.add('hidden');
    return;
  }

  const item = await api(
    `/api/assignments/${state.assignment}/submissions/latest`
  );
  const panel = $('#submission-status');
  const uploadButton = $('#upload-fab');

  if (!item) {
    const assignment = state.assignments.find(x => x.slug === state.assignment);
    if (assignment?.status === 'closed') {
      panel.innerHTML = '<strong>作业已截止</strong><div class="muted">当前为只读状态，暂无个人评测记录。</div>';
      panel.classList.remove('hidden');
    } else {
      panel.classList.add('hidden');
    }
    uploadButton.disabled = false;
    return;
  }

  panel.classList.remove('hidden');

  const labels = {
    queued: '排队中',
    preparing: '准备环境',
    installing: '准备环境',
    evaluating: '评测中',
    success: '评测完成',
    failed: '评测失败',
  };

  const score = item.status === 'success'
    ? `本次评分：综合 ${percent(item.balanced_score)} · 正确率 ${percent(item.answer_accuracy)} · 攻击识别 ${percent(item.reject_recall)}`
    : (item.error_message || '请稍候，榜单将在完成后更新');

  panel.innerHTML = `
    <div>
      <span class="status-dot ${item.status}"></span>
      <strong>${labels[item.status] || item.status}</strong>
      <div class="muted">${escapeHtml(score)}</div>
    </div>
    <small class="muted">提交于 ${timeText(item.submitted_at)}</small>
  `;

  uploadButton.disabled = [
    'queued',
    'preparing',
    'installing',
    'evaluating',
  ].includes(item.status);
}

function escapeHtml(value) { const node = document.createElement('span'); node.textContent = String(value ?? ''); return node.innerHTML; }

document.querySelectorAll('.metric-tab').forEach(button => button.addEventListener('click', async () => {
  state.sort = button.dataset.sort; document.querySelectorAll('.metric-tab').forEach(x => x.classList.toggle('active', x === button)); await loadLeaderboard();
}));
$('#refresh').addEventListener('click', async () => { await refreshAll(); toast('榜单已刷新'); });
$('#upload-fab').addEventListener('click', () => $('#zip-input').click());
$('#zip-input').addEventListener('change', async event => {
  const file = event.target.files[0];
  if (!file || !state.assignment) return;

  const uploadButton = $('#upload-fab');
  const form = new FormData();
  form.append('file', file);
  uploadButton.disabled = true;

  try {
    await api(`/api/assignments/${state.assignment}/submissions`, {
      method: 'POST',
      body: form,
    });
    toast('已加入评测队列');
    await loadSubmission();
  } catch (error) {
    toast(error.message);

    // 如果提交失败，重新读取服务端状态决定是否可以继续上传。
    try {
      await loadSubmission();
    } catch (_) {
      uploadButton.disabled = false;
    }
  } finally {
    event.target.value = '';
  }
});
$('#logout').addEventListener('click', async () => {
  try { await api('/api/auth/logout', { method: 'POST' }); } catch (_) { }
  forceLogin();
});

function forceLogin() { clearInterval(state.timer); state.session = null; state.csrf = ''; state.assignments = []; state.assignment = null; setView(false); }

bootstrap();
