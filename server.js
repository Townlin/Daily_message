// daily-message-app / server.js
// Node >=18
const express = require('express');
const session = require('express-session');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'db.json');
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(__dirname, 'backups');
const SESSION_SECRET = process.env.SESSION_SECRET || 'change-this-secret';

app.use(express.urlencoded({ extended: false }));
app.use(express.json());
app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { httpOnly: true, maxAge: 30 * 24 * 3600 * 1000 }
  })
);

// ---------- DB helpers ----------
function ensureDirs() {
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
}

function initDB() {
  if (!fs.existsSync(DATA_FILE)) {
    const db = {
      users: {
        Diane: { salt: null, hash: null },
        Rayko: { salt: null, hash: null }
      },
      messages: [] // { user, date: 'YYYY-MM-DD', text, createdAt }
    };
    fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
  }
}

function readDB() {
  return JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'));
}

function writeDB(db) {
  fs.writeFileSync(DATA_FILE, JSON.stringify(db, null, 2));
  // backups
  ensureDirs();
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  fs.writeFileSync(path.join(BACKUP_DIR, 'latest.json'), JSON.stringify(db, null, 2));
  const daily = path.join(BACKUP_DIR, `db-${y}${m}${d}.json`);
  // only write the daily snapshot once per day
  if (!fs.existsSync(daily)) fs.writeFileSync(daily, JSON.stringify(db, null, 2));
}

function setPassword(db, user, password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  db.users[user] = { salt, hash };
  writeDB(db);
}

function verifyPassword(db, user, password) {
  const u = db.users[user];
  if (!u || !u.hash || !u.salt) return false;
  const input = crypto.scryptSync(password, u.salt, 64).toString('hex');
  try {
    return crypto.timingSafeEqual(Buffer.from(u.hash, 'hex'), Buffer.from(input, 'hex'));
  } catch {
    return false;
  }
}

function todayLocal() {
  const now = new Date();
  const y = now.getFullYear();
  const m = String(now.getMonth() + 1).padStart(2, '0');
  const d = String(now.getDate()).padStart(2, '0');
  return `${y}-${m}-${d}`;
}

function countHan(s) {
  // Count Chinese Han characters only. Unicode property requires Node >= 10 + full ICU
  let c = 0;
  for (const ch of s) {
    if (/\p{Script=Han}/u.test(ch)) c++;
  }
  return c;
}

function pageLayout(title, bodyHtml, opts = {}) {
  const loggedUser = opts.user || null;
  return `<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>${title}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, Segoe UI, Roboto, Helvetica, Arial, "Noto Sans", "PingFang SC", "Hiragino Sans GB", "Microsoft YaHei", sans-serif; max-width: 720px; margin: 24px auto; padding: 0 16px; }
    header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 16px; }
    nav a { margin-right: 12px; }
    .card { border: 1px solid #ddd; border-radius: 12px; padding: 16px; margin: 12px 0; }
    .muted { color: #666; font-size: 14px; }
    input, select, textarea, button { font-size: 16px; padding: 8px; }
    textarea { width: 100%; height: 96px; }
    .err { color: #c00; }
    .ok { color: #070; }
    .row { display:flex; gap:12px; align-items:center; }
    .right { text-align:right; }
  </style>
</head>
<body>
<header>
  <div><strong>每日留言</strong></div>
  <nav>
    <a href="/">公开页</a>
    ${loggedUser ? `<span class="muted">已登录：${loggedUser}</span> <a href="/me">我的</a> <a href="/logout">退出</a>` : `<a href="/login">登录/设定密码</a>`}
  </nav>
</header>
${bodyHtml}
</body>
</html>`;
}

function messageCard(msg) {
  const when = new Date(msg.createdAt);
  const ts = `${msg.date} ${String(when.getHours()).padStart(2,'0')}:${String(when.getMinutes()).padStart(2,'0')}`;
  return `<div class="card"><div><strong>${msg.user}</strong> <span class="muted">${ts}</span></div><div style="margin-top:8px; white-space:pre-wrap;">${escapeHtml(msg.text)}</div></div>`;
}

function escapeHtml(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

// ---------- Auth middleware ----------
function requireAuth(req, res, next) {
  if (req.session && req.session.user) return next();
  res.redirect('/login');
}

// ---------- Routes ----------
initDB();
ensureDirs();

app.get('/', (req, res) => {
  const db = readDB();
  const sorted = [...db.messages].sort((a, b) => b.createdAt.localeCompare(a.createdAt));
  const body = `
    <div class="muted">每天每人限一条。当前只允许 Diane 与 Rayko 两个账号。</div>
    <div style="margin:12px 0;">
      <a href="/login">登录/设定密码</a> · <a href="/me">我的</a> · <a href="/export.json">导出JSON</a>
    </div>
    ${sorted.map(messageCard).join('') || '<div class="card muted">暂无留言</div>'}
  `;
  res.send(pageLayout('公开留言', body, { user: req.session.user }));
});

app.get('/export.json', (req, res) => {
  const db = readDB();
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.send(JSON.stringify({ users: Object.keys(db.users), messages: db.messages }, null, 2));
});

app.get('/login', (req, res) => {
  const user = req.query.user || '';
  const db = readDB();
  let content = '';
  if (!user) {
    content = `
      <div class="card">
        <form method="GET" action="/login">
          <div>选择账号：</div>
          <div class="row">
            <select name="user" required>
              <option value="">-- 选择 --</option>
              <option value="Diane">Diane</option>
              <option value="Rayko">Rayko</option>
            </select>
            <button type="submit">继续</button>
          </div>
        </form>
      </div>`;
  } else {
    if (!db.users[user]) {
      content = `<div class="card err">无效账号</div>`;
    } else if (!db.users[user].hash) {
      // set password first time
      content = `
        <div class="card">
          <div class="muted">首次登录为账号 <strong>${user}</strong> 设定密码（需输入两次确认）。</div>
          <form method="POST" action="/set-password">
            <input type="hidden" name="user" value="${user}">
            <div style="margin-top:8px;">
              <input name="password" type="password" placeholder="设置密码" required minlength="6" />
            </div>
            <div style="margin-top:8px;">
              <input name="confirm" type="password" placeholder="再次输入密码" required minlength="6" />
            </div>
            <div class="row" style="margin-top:12px;">
              <button type="submit">保存密码并登录</button>
              <a href="/login">返回</a>
            </div>
          </form>
        </div>`;
    } else {
      content = `
        <div class="card">
          <div class="muted">账号 <strong>${user}</strong> 已设定密码，请登录。</div>
          <form method="POST" action="/login">
            <input type="hidden" name="user" value="${user}">
            <div style="margin-top:8px;">
              <input name="password" type="password" placeholder="密码" required />
            </div>
            <div class="row" style="margin-top:12px;">
              <button type="submit">登录</button>
              <a href="/login">切换账号</a>
            </div>
          </form>
        </div>`;
    }
  }
  res.send(pageLayout('登录/设定密码', content, { user: req.session.user }));
});

app.post('/set-password', (req, res) => {
  const { user, password, confirm } = req.body;
  const db = readDB();
  if (!db.users[user]) return res.send(pageLayout('错误', `<div class="card err">无效账号</div>`));
  if (db.users[user].hash) return res.redirect(`/login?user=${encodeURIComponent(user)}`);
  if (!password || password !== confirm || password.length < 6)
    return res.send(pageLayout('错误', `<div class="card err">两次输入不一致或长度不足（至少6位）。</div>`));
  setPassword(db, user, password);
  req.session.user = user;
  res.redirect('/me');
});

app.post('/login', (req, res) => {
  const { user, password } = req.body;
  const db = readDB();
  if (!db.users[user] || !db.users[user].hash)
    return res.send(pageLayout('错误', `<div class="card err">账号不存在或未设定密码。</div>`));
  if (!verifyPassword(db, user, password))
    return res.send(pageLayout('错误', `<div class="card err">密码错误。</div>`));
  req.session.user = user;
  res.redirect('/me');
});

app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/');
  });
});

app.get('/me', requireAuth, (req, res) => {
  const db = readDB();
  const user = req.session.user;
  const today = todayLocal();
  const existing = db.messages.find(m => m.user === user && m.date === today);
  const info = existing
    ? `<div class="ok">今天(${today}) 已提交：<strong>${escapeHtml(existing.text)}</strong></div>`
    : `<div>今天(${today}) 还未提交。</div>`;

  const form = existing
    ? ''
    : `
      <form method="POST" action="/message" oninput="updateCount()">
        <div class="muted">限制：每日每人一条；计数以汉字为准，不含标点与空格；最多20字。</div>
        <textarea name="text" id="text" placeholder="输入留言…" maxlength="200" required></textarea>
        <div class="row">
          <div class="muted" id="counter">0 / 20（汉字计）</div>
          <div class="right" style="flex:1"></div>
          <button type="submit">提交</button>
        </div>
      </form>
      <script>
        function hanCount(s){
          let c=0; for(const ch of s){ if(/\\p{Script=Han}/u.test(ch)) c++; } return c;
        }
        function updateCount(){
          const t=document.getElementById('text').value || '';
          const c=hanCount(t);
          document.getElementById('counter').textContent = c+" / 20（汉字计）";
        }
      </script>
    `;

  const mine = db.messages.filter(m => m.user === user).sort((a,b)=>b.createdAt.localeCompare(a.createdAt));
  const body = `
    <div class="card">${info}${form}</div>
    <div class="card"><div><strong>我的历史</strong></div>${mine.map(messageCard).join('') || '<div class="muted">暂无</div>'}</div>
  `;
  res.send(pageLayout('我的', body, { user }));
});

app.post('/message', requireAuth, (req, res) => {
  const db = readDB();
  const user = req.session.user;
  const text = (req.body.text || '').trim();
  const today = todayLocal();

  // Enforce one per day per user
  if (db.messages.some(m => m.user === user && m.date === today)) {
    return res.send(pageLayout('错误', `<div class="card err">今天已提交过一条。</div>`, { user }));
  }

  const han = countHan(text);
  if (han < 1) {
    return res.send(pageLayout('错误', `<div class=\"card err\">需要至少1个汉字。</div>`, { user }));
  }
  if (han > 20) {
    return res.send(pageLayout('错误', `<div class=\"card err\">超出20个汉字限制。已计数：${han}</div>`, { user }));
  }

  db.messages.push({ user, date: today, text, createdAt: new Date().toISOString() });
  writeDB(db);
  res.redirect('/me');
});

// optional: simple health endpoint
app.get('/healthz', (req, res) => res.send('ok'));

app.listen(PORT, () => {
  console.log(`daily-message-app listening on http://localhost:${PORT}`);
});