// ============================================================
// server.js — Финансовый backend (Express + SQLite)
// ============================================================

require('dotenv').config();
const express = require('express');
const session = require('express-session');
const bcrypt = require('bcryptjs');
const path = require('path');
const fs = require('fs');
const multer = require('multer');
const nodemailer = require('nodemailer');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
  secret: process.env.SESSION_SECRET || 'change_me_please',
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 1000 * 60 * 60 * 12 } // 12 часов
}));

// ==================== ВСПОМОГАТЕЛЬНОЕ ====================

const PASSWORD_MAX_AGE_DAYS = 30;
const ALLOWED_WHEN_PASSWORD_EXPIRED = ['/api/profile', '/api/change-password'];

function isPasswordExpired(userId) {
  const row = db.prepare('SELECT password_changed_at FROM users WHERE id = ?').get(userId);
  if (!row || !row.password_changed_at) return false;
  // SQLite datetime('now') хранит UTC без суффикса — явно указываем это при парсинге
  const changed = new Date(row.password_changed_at.replace(' ', 'T') + 'Z');
  if (isNaN(changed.getTime())) return false;
  const ageDays = (Date.now() - changed.getTime()) / 86400000;
  return ageDays >= PASSWORD_MAX_AGE_DAYS;
}

function requireAuth(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Не авторизован' });
  if (isPasswordExpired(req.session.user.id) && !ALLOWED_WHEN_PASSWORD_EXPIRED.includes(req.path)) {
    return res.status(403).json({
      error: 'Срок действия пароля истёк (30 дней) — смените пароль в профиле, чтобы продолжить',
      code: 'password_expired'
    });
  }
  next();
}

function requireOwner(req, res, next) {
  if (!req.session.user || req.session.user.role !== 'owner') {
    return res.status(403).json({ error: 'Доступно только владельцу' });
  }
  next();
}

// Владелец и бухгалтер — полные права редактирования (кроме лимитов бюджета, там строго requireOwner)
function requireEditor(req, res, next) {
  if (!req.session.user || (req.session.user.role !== 'owner' && req.session.user.role !== 'accountant')) {
    return res.status(403).json({ error: 'Недостаточно прав для этого действия' });
  }
  next();
}

function logAudit(action, entity, entityId, performedBy, details) {
  db.prepare(`
    INSERT INTO audit_log (action, entity, entity_id, performed_by, details)
    VALUES (?, ?, ?, ?, ?)
  `).run(action, entity, String(entityId ?? ''), performedBy || 'unknown', details ? JSON.stringify(details) : null);
}

async function sendTelegramMessage(text, chatId) {
  const token = process.env.TELEGRAM_TOKEN;
  const targetChatId = chatId || process.env.TELEGRAM_CHAT_ID;
  if (!token || !targetChatId) return; // Telegram не настроен для этого адресата — тихо пропускаем
  try {
    await fetch(`https://api.telegram.org/bot${token}/sendMessage`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chat_id: targetChatId, text, parse_mode: 'Markdown' })
    });
  } catch (err) {
    console.error('Ошибка отправки в Telegram:', err.message);
  }
}

function fmt(n) {
  return Math.round(n).toLocaleString('ru-RU') + ' ₽';
}

// ==================== EMAIL (для восстановления пароля) ====================

let mailTransporter = null;
if (process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASS) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT) || 587,
    secure: process.env.SMTP_SECURE === 'true',
    auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
  });
  console.log('✓ SMTP настроен, email-уведомления доступны');
} else {
  console.log('ℹ SMTP не настроен — восстановление пароля по email работать не будет (только Telegram)');
}

async function sendEmail(to, subject, text) {
  if (!mailTransporter) {
    console.warn(`SMTP не настроен. Письмо для ${to} не отправлено. Тема: "${subject}"`);
    return false;
  }
  try {
    await mailTransporter.sendMail({ from: process.env.SMTP_FROM || process.env.SMTP_USER, to, subject, text });
    return true;
  } catch (err) {
    console.error('Ошибка отправки email:', err.message);
    return false;
  }
}

function nowMoscow() {
  return new Date().toLocaleString('ru-RU', {
    timeZone: 'Europe/Moscow',
    day: '2-digit', month: '2-digit', year: 'numeric',
    hour: '2-digit', minute: '2-digit'
  });
}

// ==================== АВТОРИЗАЦИЯ ====================

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;

app.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);

  if (!user) {
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }

  // Проверка активной блокировки
  if (user.locked_until && new Date(user.locked_until) > new Date()) {
    const minutesLeft = Math.ceil((new Date(user.locked_until) - new Date()) / 60000);
    return res.status(423).json({
      error: `Аккаунт временно заблокирован из-за неверных попыток входа. Попробуйте снова через ${minutesLeft} мин.`
    });
  }

  if (!bcrypt.compareSync(password || '', user.password_hash)) {
    const attempts = (user.failed_login_attempts || 0) + 1;
    if (attempts >= MAX_LOGIN_ATTEMPTS) {
      const lockedUntil = new Date(Date.now() + LOCKOUT_DURATION_MINUTES * 60000).toISOString();
      db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = ? WHERE id = ?').run(lockedUntil, user.id);
      logAudit('update', 'users', user.id, username, { action: 'account_locked' });
      return res.status(423).json({
        error: `Неверный пароль. Аккаунт заблокирован на ${LOCKOUT_DURATION_MINUTES} минут из-за 5 неверных попыток подряд.`
      });
    }
    db.prepare('UPDATE users SET failed_login_attempts = ? WHERE id = ?').run(attempts, user.id);
    return res.status(401).json({
      error: `Неверный логин или пароль. Осталось попыток: ${MAX_LOGIN_ATTEMPTS - attempts}`,
      attemptsLeft: MAX_LOGIN_ATTEMPTS - attempts
    });
  }

  // Успешный вход — сбрасываем счётчик и блокировку
  db.prepare('UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
  req.session.user = { id: user.id, username: user.username, role: user.role };
  res.json({ ok: true, user: req.session.user });
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

// ==================== ВОССТАНОВЛЕНИЕ ПАРОЛЯ ====================
// Код действителен 15 минут, одноразовый. Ответ всегда одинаковый вне
// зависимости от того, существует ли пользователь — чтобы не палить список логинов.

const RESET_CODE_TTL_MINUTES = 15;
const GENERIC_RESET_RESPONSE = {
  ok: true,
  message: 'Если такой пользователь существует и у него указан выбранный канал связи в профиле, код отправлен.'
};

app.post('/api/forgot-password', async (req, res) => {
  const { username, channel } = req.body;
  if (!username || !['email', 'telegram'].includes(channel)) {
    return res.status(400).json({ error: 'Обязательны: username, channel (email или telegram)' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user) return res.json(GENERIC_RESET_RESPONSE);

  if (channel === 'email' && !user.email) {
    return res.status(400).json({ error: 'У этого пользователя не указан email в профиле — попросите его заполнить профиль или используйте Telegram' });
  }
  if (channel === 'telegram' && !user.telegram_chat_id) {
    return res.status(400).json({ error: 'У этого пользователя не указан личный Telegram Chat ID в профиле — попросите его заполнить профиль или используйте email' });
  }

  const code = String(Math.floor(100000 + Math.random() * 900000));
  const expires = new Date(Date.now() + RESET_CODE_TTL_MINUTES * 60000).toISOString();
  db.prepare('UPDATE users SET reset_token = ?, reset_token_expires = ? WHERE id = ?').run(code, expires, user.id);

  if (channel === 'email') {
    await sendEmail(
      user.email,
      'Восстановление пароля — AI Finance',
      `Код для восстановления пароля: ${code}\nДействителен ${RESET_CODE_TTL_MINUTES} минут.\nЕсли это были не вы — просто проигнорируйте это письмо.`
    );
  } else {
    await sendTelegramMessage(
      `🔐 *Восстановление пароля AI Finance*\nКод: *${code}*\nДействителен ${RESET_CODE_TTL_MINUTES} минут.\nЕсли это были не вы — проигнорируйте сообщение.`,
      user.telegram_chat_id
    );
  }

  res.json(GENERIC_RESET_RESPONSE);
});

app.post('/api/reset-password', (req, res) => {
  const { username, code, newPassword } = req.body;
  if (!username || !code || !newPassword) {
    return res.status(400).json({ error: 'Обязательны: username, code, newPassword' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Новый пароль должен быть не короче 6 символов' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!user || !user.reset_token || user.reset_token !== code) {
    return res.status(400).json({ error: 'Неверный код' });
  }
  if (!user.reset_token_expires || new Date(user.reset_token_expires) < new Date()) {
    return res.status(400).json({ error: 'Срок действия кода истёк — запросите новый' });
  }

  const hash = bcrypt.hashSync(newPassword, 10);
  db.prepare(`
    UPDATE users SET password_hash = ?, password_changed_at = datetime('now'), reset_token = NULL, reset_token_expires = NULL
    WHERE id = ?
  `).run(hash, user.id);
  logAudit('update', 'users', user.id, 'system', { action: 'password_reset_via_code' });
  res.json({ ok: true });
});

app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json({ user: null });
  res.json({ user: req.session.user, mustChangePassword: isPasswordExpired(req.session.user.id) });
});

// ==================== ПРОФИЛЬ ПОЛЬЗОВАТЕЛЯ ====================

app.get('/api/profile', requireAuth, (req, res) => {
  const user = db.prepare(`
    SELECT id, username, role, full_name, email, phone, telegram_chat_id, telegram_username, position, created_at
    FROM users WHERE id = ?
  `).get(req.session.user.id);
  res.json(user);
});

app.put('/api/profile', requireAuth, (req, res) => {
  const { full_name, email, phone, telegram_chat_id, telegram_username } = req.body;
  db.prepare(`
    UPDATE users SET full_name = ?, email = ?, phone = ?, telegram_chat_id = ?, telegram_username = ? WHERE id = ?
  `).run(full_name || null, email || null, phone || null, telegram_chat_id || null, telegram_username || null, req.session.user.id);
  logAudit('update', 'users', req.session.user.id, req.session.user.username, { full_name, email, phone });
  res.json({ ok: true });
});

app.post('/api/change-password', requireAuth, (req, res) => {
  const { currentPassword, newPassword } = req.body;
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'Обязательны: currentPassword, newPassword' });
  }
  if (newPassword.length < 6) {
    return res.status(400).json({ error: 'Новый пароль должен быть не короче 6 символов' });
  }
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.user.id);
  if (!bcrypt.compareSync(currentPassword, user.password_hash)) {
    return res.status(401).json({ error: 'Текущий пароль неверен' });
  }
  const newHash = bcrypt.hashSync(newPassword, 10);
  db.prepare(`UPDATE users SET password_hash = ?, password_changed_at = datetime('now') WHERE id = ?`).run(newHash, req.session.user.id);
  logAudit('update', 'users', req.session.user.id, req.session.user.username, { action: 'password_changed' });
  res.json({ ok: true });
});

// ==================== СПРАВОЧНИК КОЛЛЕГ ====================
// Видно всем авторизованным пользователям; пароли никогда не отдаются.

app.get('/api/users', requireAuth, (req, res) => {
  const users = db.prepare(`
    SELECT id, username, role, full_name, email, phone, position, telegram_username
    FROM users ORDER BY role DESC, username
  `).all();
  res.json(users);
});

app.post('/api/users', requireEditor, (req, res) => {
  const { username, password, role, full_name, email, phone, position, telegram_username } = req.body;
  if (!username || !password || !role) {
    return res.status(400).json({ error: 'Обязательны: username, password, role' });
  }
  if (!['owner', 'accountant', 'user'].includes(role)) {
    return res.status(400).json({ error: 'role должен быть owner или accountant' });
  }
  if (password.length < 6) {
    return res.status(400).json({ error: 'Пароль должен быть не короче 6 символов' });
  }
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return res.status(400).json({ error: 'Такой логин уже занят' });

  const hash = bcrypt.hashSync(password, 10);
  const info = db.prepare(`
    INSERT INTO users (username, password_hash, role, full_name, email, phone, position, telegram_username, password_changed_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
  `).run(username, hash, role, full_name || null, email || null, phone || null, position || null, telegram_username || null);

  logAudit('create', 'users', info.lastInsertRowid, req.session.user.username, { username, role });
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.get('/api/users/:id', requireEditor, (req, res) => {
  const user = db.prepare(`
    SELECT id, username, role, full_name, email, phone, position, telegram_username FROM users WHERE id = ?
  `).get(req.params.id);
  if (!user) return res.status(404).json({ error: 'Пользователь не найден' });
  res.json(user);
});

app.put('/api/users/:id', requireEditor, (req, res) => {
  const targetId = Number(req.params.id);
  const existing = db.prepare('SELECT * FROM users WHERE id = ?').get(targetId);
  if (!existing) return res.status(404).json({ error: 'Пользователь не найден' });

  const { role, full_name, email, phone, position, telegram_username, newPassword } = req.body;

  if (role && !['owner', 'accountant', 'user'].includes(role)) {
    return res.status(400).json({ error: 'role должен быть owner или accountant' });
  }
  if (role && role !== 'owner' && existing.role === 'owner') {
    const ownerCount = db.prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'owner'`).get().c;
    if (ownerCount <= 1) return res.status(400).json({ error: 'Должен остаться хотя бы один владелец' });
  }

  db.prepare(`
    UPDATE users SET role = ?, full_name = ?, email = ?, phone = ?, position = ?, telegram_username = ?
    WHERE id = ?
  `).run(
    role ?? existing.role, full_name ?? existing.full_name, email ?? existing.email,
    phone ?? existing.phone, position ?? existing.position, telegram_username ?? existing.telegram_username,
    targetId
  );

  if (newPassword) {
    if (newPassword.length < 6) return res.status(400).json({ error: 'Новый пароль должен быть не короче 6 символов' });
    const hash = bcrypt.hashSync(newPassword, 10);
    db.prepare(`UPDATE users SET password_hash = ?, password_changed_at = datetime('now') WHERE id = ?`).run(hash, targetId);
  }

  logAudit('update', 'users', targetId, req.session.user.username, { role, full_name, email, phone, position });
  res.json({ ok: true });
});

app.delete('/api/users/:id', requireEditor, (req, res) => {
  const targetId = Number(req.params.id);
  if (targetId === req.session.user.id) {
    return res.status(400).json({ error: 'Нельзя удалить самого себя, пока вы в неё вошли' });
  }
  const target = db.prepare('SELECT * FROM users WHERE id = ?').get(targetId);
  if (!target) return res.status(404).json({ error: 'Пользователь не найден' });
  const ownerCount = db.prepare(`SELECT COUNT(*) AS c FROM users WHERE role = 'owner'`).get().c;
  if (target.role === 'owner' && ownerCount <= 1) {
    return res.status(400).json({ error: 'Должен остаться хотя бы один владелец' });
  }
  db.prepare('DELETE FROM users WHERE id = ?').run(targetId);
  logAudit('delete', 'users', targetId, req.session.user.username, { username: target.username });
  res.json({ ok: true });
});

// ==================== ВНУТРЕННИЙ ЧАТ (личные + групповые беседы) ====================

const chatUploadDir = path.join(__dirname, 'uploads', 'chat');
fs.mkdirSync(chatUploadDir, { recursive: true });

const chatUpload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, chatUploadDir),
    filename: (req, file, cb) => {
      const safe = file.originalname.replace(/[^a-zA-Zа-яА-Я0-9._-]/g, '_');
      cb(null, `${Date.now()}_${safe}`);
    }
  }),
  limits: { fileSize: 150 * 1024 * 1024 } // 150 МБ на файл
});

function isMember(conversationId, userId) {
  return !!db.prepare('SELECT 1 FROM conversation_members WHERE conversation_id = ? AND user_id = ?').get(conversationId, userId);
}

function conversationDisplayInfo(conv, meId) {
  if (conv.type === 'group') return { name: conv.name || 'Группа', isGroup: true };
  const other = db.prepare(`
    SELECT u.id, u.username, u.full_name, u.role FROM conversation_members cm
    JOIN users u ON u.id = cm.user_id
    WHERE cm.conversation_id = ? AND cm.user_id != ?
  `).get(conv.id, meId);
  return { name: other ? (other.full_name || other.username) : 'Диалог', isGroup: false, otherUser: other };
}

// Список всех бесед пользователя (личные + групповые) с последним сообщением и непрочитанными
// Лёгкий endpoint только с числом непрочитанных — для значка в шапке на всех страницах
app.get('/api/chat/unread-count', requireAuth, (req, res) => {
  const meId = req.session.user.id;
  const members = db.prepare(`
    SELECT conversation_id, last_read_message_id FROM conversation_members WHERE user_id = ?
  `).all(meId);
  let total = 0;
  members.forEach(m => {
    total += db.prepare(`
      SELECT COUNT(*) AS c FROM chat_messages WHERE conversation_id = ? AND id > ? AND sender_id != ?
    `).get(m.conversation_id, m.last_read_message_id || 0, meId).c;
  });
  res.json({ unread: total });
});

app.get('/api/chat/conversations', requireAuth, (req, res) => {
  const meId = req.session.user.id;
  const convs = db.prepare(`
    SELECT c.* FROM conversations c
    JOIN conversation_members cm ON cm.conversation_id = c.id
    WHERE cm.user_id = ?
  `).all(meId);

  const result = convs.map(conv => {
    const info = conversationDisplayInfo(conv, meId);
    const lastMsg = db.prepare(`
      SELECT * FROM chat_messages WHERE conversation_id = ? ORDER BY id DESC LIMIT 1
    `).get(conv.id);
    const member = db.prepare(`
      SELECT last_read_message_id, pinned_at FROM conversation_members WHERE conversation_id = ? AND user_id = ?
    `).get(conv.id, meId);
    const unread = db.prepare(`
      SELECT COUNT(*) AS cnt FROM chat_messages
      WHERE conversation_id = ? AND id > ? AND sender_id != ?
    `).get(conv.id, member?.last_read_message_id || 0, meId).cnt;

    return {
      id: conv.id,
      type: conv.type,
      name: info.name,
      lastMessage: lastMsg ? (lastMsg.body || (lastMsg.attachment_filename ? '📎 ' + lastMsg.attachment_filename : '')) : '',
      lastMessageAt: lastMsg ? lastMsg.created_at : conv.created_at,
      unread,
      pinned: !!(member && member.pinned_at)
    };
  }).sort((a, b) => {
    if (a.pinned !== b.pinned) return a.pinned ? -1 : 1;
    return new Date(b.lastMessageAt) - new Date(a.lastMessageAt);
  });

  res.json(result);
});

// Закрепить/открепить беседу (индивидуально для каждого пользователя)
app.put('/api/chat/conversations/:id/pin', requireAuth, (req, res) => {
  const convId = req.params.id;
  const meId = req.session.user.id;
  if (!isMember(convId, meId)) return res.status(403).json({ error: 'Нет доступа к этой беседе' });
  const { pinned } = req.body;
  db.prepare(`
    UPDATE conversation_members SET pinned_at = ? WHERE conversation_id = ? AND user_id = ?
  `).run(pinned ? new Date().toISOString() : null, convId, meId);
  res.json({ ok: true });
});

// Найти или создать личную беседу с конкретным коллегой
app.post('/api/chat/dm/:userId', requireAuth, (req, res) => {
  const meId = req.session.user.id;
  const otherId = Number(req.params.userId);
  const other = db.prepare('SELECT id FROM users WHERE id = ?').get(otherId);
  if (!other) return res.status(404).json({ error: 'Пользователь не найден' });

  const existing = db.prepare(`
    SELECT c.id FROM conversations c
    JOIN conversation_members m1 ON m1.conversation_id = c.id AND m1.user_id = ?
    JOIN conversation_members m2 ON m2.conversation_id = c.id AND m2.user_id = ?
    WHERE c.type = 'dm'
  `).get(meId, otherId);
  if (existing) return res.json({ id: existing.id });

  const info = db.prepare(`INSERT INTO conversations (type, created_by) VALUES ('dm', ?)`).run(meId);
  db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)').run(info.lastInsertRowid, meId);
  db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)').run(info.lastInsertRowid, otherId);
  res.json({ id: info.lastInsertRowid });
});

// Создать групповую беседу
app.post('/api/chat/groups', requireAuth, (req, res) => {
  const meId = req.session.user.id;
  const { name, memberIds } = req.body;
  if (!name || !name.trim()) return res.status(400).json({ error: 'Укажите название группы' });
  const members = Array.from(new Set([meId, ...(memberIds || []).map(Number)]));

  const info = db.prepare(`INSERT INTO conversations (type, name, created_by) VALUES ('group', ?, ?)`).run(name.trim(), meId);
  const insertMember = db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)');
  members.forEach(uid => insertMember.run(info.lastInsertRowid, uid));
  res.json({ id: info.lastInsertRowid });
});

// Список участников беседы
app.get('/api/chat/conversations/:id/members', requireAuth, (req, res) => {
  const convId = req.params.id;
  if (!isMember(convId, req.session.user.id)) return res.status(403).json({ error: 'Нет доступа к этой беседе' });
  const members = db.prepare(`
    SELECT u.id, u.username, u.full_name, u.role FROM conversation_members cm
    JOIN users u ON u.id = cm.user_id WHERE cm.conversation_id = ?
  `).all(convId);
  res.json(members);
});

// Добавить участника в группу
app.post('/api/chat/conversations/:id/members', requireAuth, (req, res) => {
  const convId = req.params.id;
  const meId = req.session.user.id;
  if (!isMember(convId, meId)) return res.status(403).json({ error: 'Нет доступа к этой беседе' });
  const conv = db.prepare('SELECT * FROM conversations WHERE id = ?').get(convId);
  if (!conv || conv.type !== 'group') return res.status(400).json({ error: 'Добавлять участников можно только в группу' });
  const { userId } = req.body;
  if (!userId) return res.status(400).json({ error: 'Обязателен userId' });
  const already = isMember(convId, userId);
  if (!already) {
    db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)').run(convId, userId);
  }
  res.json({ ok: true });
});

// История сообщений беседы (и отметка как прочитано)
app.get('/api/chat/conversations/:id/messages', requireAuth, (req, res) => {
  const convId = req.params.id;
  const meId = req.session.user.id;
  if (!isMember(convId, meId)) return res.status(403).json({ error: 'Нет доступа к этой беседе' });

  const rows = db.prepare(`
    SELECT cm.*, u.username, u.full_name FROM chat_messages cm
    JOIN users u ON u.id = cm.sender_id
    WHERE cm.conversation_id = ? ORDER BY cm.id ASC
  `).all(convId);

  const lastId = rows.length ? rows[rows.length - 1].id : 0;
  db.prepare(`
    UPDATE conversation_members SET last_read_message_id = ? WHERE conversation_id = ? AND user_id = ?
  `).run(lastId, convId, meId);

  res.json(rows);
});

// Очистка истории беседы — только владелец (полные права)
app.delete('/api/chat/conversations/:id/messages', requireOwner, (req, res) => {
  const convId = req.params.id;
  if (!isMember(convId, req.session.user.id)) return res.status(403).json({ error: 'Нет доступа к этой беседе' });

  const attachments = db.prepare(`
    SELECT attachment_path FROM chat_messages WHERE conversation_id = ? AND attachment_path IS NOT NULL
  `).all(convId);
  attachments.forEach(a => {
    try { fs.unlinkSync(path.join(chatUploadDir, a.attachment_path)); } catch (e) { /* файла уже нет — не страшно */ }
  });

  db.prepare('DELETE FROM chat_messages WHERE conversation_id = ?').run(convId);
  db.prepare('UPDATE conversation_members SET last_read_message_id = 0 WHERE conversation_id = ?').run(convId);
  logAudit('delete', 'chat_messages', convId, req.session.user.username, { action: 'clear_history' });
  res.json({ ok: true });
});

// Отправка текстового сообщения
app.post('/api/chat/conversations/:id/messages', requireAuth, (req, res) => {
  const convId = req.params.id;
  const meId = req.session.user.id;
  if (!isMember(convId, meId)) return res.status(403).json({ error: 'Нет доступа к этой беседе' });
  const body = (req.body.body || '').trim();
  if (!body) return res.status(400).json({ error: 'Пустое сообщение' });
  const info = db.prepare(`
    INSERT INTO chat_messages (conversation_id, sender_id, body) VALUES (?, ?, ?)
  `).run(convId, meId, body);
  res.json({ ok: true, id: info.lastInsertRowid });
});

// Отправка файла (вложения)
app.post('/api/chat/conversations/:id/attachments', requireAuth, chatUpload.single('file'), (req, res) => {
  const convId = req.params.id;
  const meId = req.session.user.id;
  if (!isMember(convId, meId)) return res.status(403).json({ error: 'Нет доступа к этой беседе' });
  if (!req.file) return res.status(400).json({ error: 'Файл не получен' });

  const info = db.prepare(`
    INSERT INTO chat_messages (conversation_id, sender_id, attachment_filename, attachment_path, attachment_mimetype)
    VALUES (?, ?, ?, ?, ?)
  `).run(convId, meId, req.file.originalname, req.file.filename, req.file.mimetype);
  res.json({ ok: true, id: info.lastInsertRowid });
});

// Скачивание вложения (с проверкой, что запрашивающий — участник беседы этого сообщения)
app.get('/api/chat/attachments/:messageId', requireAuth, (req, res) => {
  const msg = db.prepare('SELECT * FROM chat_messages WHERE id = ?').get(req.params.messageId);
  if (!msg || !msg.attachment_path) return res.status(404).json({ error: 'Файл не найден' });
  if (!isMember(msg.conversation_id, req.session.user.id)) return res.status(403).json({ error: 'Нет доступа' });
  res.download(path.join(chatUploadDir, msg.attachment_path), msg.attachment_filename);
});

// ==================== ОРГАНИЗАЦИИ (ООО / ИП) ====================

const TAX_REGIMES = [
  'УСН 6% (доходы)',
  'УСН 15% (доходы минус расходы)',
  'ОСНО',
  'ПСН (патент)',
  'ЕСХН'
];

app.get('/api/organizations', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM organizations ORDER BY id').all();
  res.json({ organizations: rows, availableRegimes: TAX_REGIMES });
});

app.post('/api/organizations', requireEditor, (req, res) => {
  const {
    name, legal_form, inn, kpp, ogrn, legal_address, postal_address,
    phone, contact_person, tax_regime, tax_rate, patent_cost_yearly
  } = req.body;
  if (!name || !legal_form) return res.status(400).json({ error: 'Обязательны: name, legal_form' });
  if (!['ООО', 'ИП'].includes(legal_form)) return res.status(400).json({ error: 'legal_form должен быть ООО или ИП' });
  if (tax_regime === 'ПСН (патент)' && legal_form !== 'ИП') {
    return res.status(400).json({ error: 'Патент (ПСН) доступен только для ИП' });
  }

  const info = db.prepare(`
    INSERT INTO organizations
      (name, legal_form, inn, kpp, ogrn, legal_address, postal_address, phone, contact_person, tax_regime, tax_rate, patent_cost_yearly)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    name, legal_form, inn || null, kpp || null, ogrn || null,
    legal_address || null, postal_address || null, phone || null, contact_person || null,
    tax_regime || 'УСН 6% (доходы)',
    tax_rate ? Number(tax_rate) : null, patent_cost_yearly ? Number(patent_cost_yearly) : null
  );

  logAudit('create', 'organizations', info.lastInsertRowid, req.session.user.username, req.body);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/organizations/:id', requireEditor, (req, res) => {
  const {
    name, legal_form, inn, kpp, ogrn, legal_address, postal_address,
    phone, contact_person, tax_regime, tax_rate, patent_cost_yearly
  } = req.body;
  const existing = db.prepare('SELECT * FROM organizations WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Организация не найдена' });
  if (tax_regime === 'ПСН (патент)' && (legal_form || existing.legal_form) !== 'ИП') {
    return res.status(400).json({ error: 'Патент (ПСН) доступен только для ИП' });
  }

  db.prepare(`
    UPDATE organizations SET
      name = ?, legal_form = ?, inn = ?, kpp = ?, ogrn = ?,
      legal_address = ?, postal_address = ?, phone = ?, contact_person = ?,
      tax_regime = ?, tax_rate = ?, patent_cost_yearly = ?
    WHERE id = ?
  `).run(
    name ?? existing.name, legal_form ?? existing.legal_form, inn ?? existing.inn,
    kpp ?? existing.kpp, ogrn ?? existing.ogrn,
    legal_address ?? existing.legal_address, postal_address ?? existing.postal_address,
    phone ?? existing.phone, contact_person ?? existing.contact_person,
    tax_regime ?? existing.tax_regime,
    tax_rate !== undefined ? (tax_rate ? Number(tax_rate) : null) : existing.tax_rate,
    patent_cost_yearly !== undefined ? (patent_cost_yearly ? Number(patent_cost_yearly) : null) : existing.patent_cost_yearly,
    req.params.id
  );

  logAudit('update', 'organizations', req.params.id, req.session.user.username, req.body);
  res.json({ ok: true });
});

app.delete('/api/organizations/:id', requireEditor, (req, res) => {
  const txCount = db.prepare('SELECT COUNT(*) AS c FROM transactions WHERE organization_id = ?').get(req.params.id).c;
  if (txCount > 0) {
    return res.status(400).json({ error: `Нельзя удалить: у организации есть ${txCount} операций. Сначала перенесите или удалите их.` });
  }
  const orgCount = db.prepare('SELECT COUNT(*) AS c FROM organizations').get().c;
  if (orgCount <= 1) {
    return res.status(400).json({ error: 'Должна остаться хотя бы одна организация' });
  }
  db.prepare('DELETE FROM organizations WHERE id = ?').run(req.params.id);
  logAudit('delete', 'organizations', req.params.id, req.session.user.username);
  res.json({ ok: true });
});

// ==================== РАСЧЁТ НАЛОГОВОЙ НАГРУЗКИ (ОРИЕНТИРОВОЧНО) ====================
// ВАЖНО: это упрощённый ориентировочный расчёт для планирования, а не
// официальная налоговая декларация. Для точных сумм и подачи отчётности
// нужен бухгалтер или налоговый консультант.

// ==================== СОТРУДНИКИ (для детального учёта зарплаты) ====================

const PAYROLL_TYPES = ['Оклад/Зарплата', 'Аванс', 'Больничный', 'Отпускные', 'Отпуск за свой счёт', 'Премия', 'Компенсация при увольнении', 'Другое'];

app.get('/api/employees', requireAuth, (req, res) => {
  const { organization_id } = req.query;
  if (!organization_id) return res.status(400).json({ error: 'Обязателен organization_id' });
  const rows = db.prepare(`
    SELECT * FROM employees WHERE organization_id = ? ORDER BY status ASC, full_name
  `).all(organization_id);
  res.json({ employees: rows, payrollTypes: PAYROLL_TYPES });
});

app.post('/api/employees', requireEditor, (req, res) => {
  const {
    organization_id, full_name, position, department, status, official_salary, unofficial_salary,
    phone_work, phone_personal, email_work, telegram_username
  } = req.body;
  if (!organization_id || !full_name) return res.status(400).json({ error: 'Обязательны: organization_id, full_name' });
  const info = db.prepare(`
    INSERT INTO employees
      (organization_id, full_name, position, department, status, official_salary, unofficial_salary,
       phone_work, phone_personal, email_work, telegram_username)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(organization_id, full_name.trim(), position || null, department || null, status || 'active',
         Number(official_salary) || 0, Number(unofficial_salary) || 0,
         phone_work || null, phone_personal || null, email_work || null, telegram_username || null);
  logAudit('create', 'employees', info.lastInsertRowid, req.session.user.username, req.body);

  const org = db.prepare('SELECT name FROM organizations WHERE id = ?').get(organization_id);
  let msg = `👤 *Новый сотрудник добавлен*\n━━━━━━━━━━━━━━━━━━\n`;
  if (org) msg += `🏢 Организация: ${org.name}\n`;
  msg += `ФИО: ${full_name.trim()}\n`;
  if (position) msg += `Должность: ${position}\n`;
  msg += `💼 Официальная ЗП: ${fmt(Number(official_salary) || 0)}\n💵 Неофициальная ЗП: ${fmt(Number(unofficial_salary) || 0)}\n`;
  msg += `Добавил: ${req.session.user.username}`;
  sendTelegramMessage(msg);

  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/employees/:id', requireEditor, (req, res) => {
  const {
    full_name, position, department, status, official_salary, unofficial_salary,
    phone_work, phone_personal, email_work, telegram_username
  } = req.body;
  const existing = db.prepare('SELECT * FROM employees WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Сотрудник не найден' });

  const newOfficial = official_salary !== undefined ? (Number(official_salary) || 0) : existing.official_salary;
  const newUnofficial = unofficial_salary !== undefined ? (Number(unofficial_salary) || 0) : existing.unofficial_salary;

  db.prepare(`
    UPDATE employees SET
      full_name = ?, position = ?, department = ?, status = ?, official_salary = ?, unofficial_salary = ?,
      phone_work = ?, phone_personal = ?, email_work = ?, telegram_username = ?
    WHERE id = ?
  `).run(
    full_name ?? existing.full_name, position ?? existing.position, department !== undefined ? department : existing.department,
    status ?? existing.status, newOfficial, newUnofficial,
    phone_work !== undefined ? phone_work : existing.phone_work,
    phone_personal !== undefined ? phone_personal : existing.phone_personal,
    email_work !== undefined ? email_work : existing.email_work,
    telegram_username !== undefined ? telegram_username : existing.telegram_username,
    req.params.id
  );

  // ---- Уведомление в Telegram о любой корректировке ЗП ----
  const officialChanged = newOfficial !== existing.official_salary;
  const unofficialChanged = newUnofficial !== existing.unofficial_salary;
  if (officialChanged || unofficialChanged) {
    const org = db.prepare('SELECT name FROM organizations WHERE id = ?').get(existing.organization_id);
    let msg = `✏️ *Корректировка зарплаты сотрудника*\n━━━━━━━━━━━━━━━━━━\n`;
    if (org) msg += `🏢 Организация: ${org.name}\n`;
    msg += `👤 Сотрудник: ${existing.full_name}\n`;
    if (officialChanged) msg += `💼 Официальная ЗП: ${fmt(existing.official_salary || 0)} → ${fmt(newOfficial)}\n`;
    if (unofficialChanged) msg += `💵 Неофициальная ЗП: ${fmt(existing.unofficial_salary || 0)} → ${fmt(newUnofficial)}\n`;
    msg += `━━━━━━━━━━━━━━━━━━\n🕐 ${nowMoscow()} (МСК)\nИзменил: ${req.session.user.username}`;
    sendTelegramMessage(msg);
  }

  logAudit('update', 'employees', req.params.id, req.session.user.username, req.body);
  res.json({ ok: true });
});

app.delete('/api/employees/:id', requireEditor, (req, res) => {
  const txCount = db.prepare('SELECT COUNT(*) AS c FROM transactions WHERE employee_id = ?').get(req.params.id).c;
  if (txCount > 0) {
    return res.status(400).json({ error: `У сотрудника есть ${txCount} начислений в истории. Пометьте его как "уволен" вместо удаления, чтобы сохранить историю выплат.` });
  }
  db.prepare('DELETE FROM employees WHERE id = ?').run(req.params.id);
  logAudit('delete', 'employees', req.params.id, req.session.user.username);
  res.json({ ok: true });
});

// ==================== ТАБЕЛЬ ПОСЕЩАЕМОСТИ ====================
// Доступен всем авторизованным ролям (владелец, бухгалтер, обычный пользователь/делопроизводитель).
// Логика: у каждого сотрудника есть официальная ЗП за месяц. Стандартный день — 8 часов.
// Часовая ставка = официальная ЗП / (кол-во рабочих дней в месяце × 8).
// Итоговая расчётная ЗП = официальная ЗП + (фактически отработанные часы − стандартные часы) × часовая ставка.
// Прогул/выходной за свой счёт — просто 0 часов в этот день, что автоматически уменьшает итог по формуле выше.

function countWorkdaysInMonth(year, month) {
  // month: 1-12. Считаем будни (Пн-Пт) без учёта официальных праздников РФ — ориентировочно.
  const daysInMonth = new Date(year, month, 0).getDate();
  let workdays = 0;
  for (let d = 1; d <= daysInMonth; d++) {
    const dow = new Date(year, month - 1, d).getDay(); // 0=вс, 6=сб
    if (dow !== 0 && dow !== 6) workdays++;
  }
  return workdays;
}

function isWeekend(year, month, day) {
  const dow = new Date(year, month - 1, day).getDay();
  return dow === 0 || dow === 6;
}

// Табель одного сотрудника за месяц (для сетки в интерфейсе)
app.get('/api/attendance', requireAuth, (req, res) => {
  const { employee_id, month } = req.query; // month: 'YYYY-MM'
  if (!employee_id || !month) return res.status(400).json({ error: 'Обязательны: employee_id, month' });
  const rows = db.prepare(`
    SELECT date, hours, note FROM attendance WHERE employee_id = ? AND date LIKE ?
  `).all(employee_id, month + '-%');
  const byDate = {};
  rows.forEach(r => { byDate[r.date] = { hours: r.hours, note: r.note }; });
  res.json({ days: byDate });
});

// Сохранить/обновить один день табеля
app.put('/api/attendance', requireAuth, (req, res) => {
  const { employee_id, date, hours, note } = req.body;
  if (!employee_id || !date) return res.status(400).json({ error: 'Обязательны: employee_id, date' });
  db.prepare(`
    INSERT INTO attendance (employee_id, date, hours, note, updated_by, updated_at)
    VALUES (?, ?, ?, ?, ?, datetime('now'))
    ON CONFLICT(employee_id, date) DO UPDATE SET
      hours = excluded.hours, note = excluded.note, updated_by = excluded.updated_by, updated_at = datetime('now')
  `).run(employee_id, date, Number(hours) || 0, note || null, req.session.user.username);
  res.json({ ok: true });
});

// Массово проставить 8 часов на все рабочие дни месяца (не трогая уже заполненные дни)
app.post('/api/attendance/fill-standard', requireAuth, (req, res) => {
  const { employee_id, month, overwrite } = req.body; // month: 'YYYY-MM'
  if (!employee_id || !month) return res.status(400).json({ error: 'Обязательны: employee_id, month' });
  const [year, mon] = month.split('-').map(Number);
  const daysInMonth = new Date(year, mon, 0).getDate();

  const existing = db.prepare(`SELECT date FROM attendance WHERE employee_id = ? AND date LIKE ?`).all(employee_id, month + '-%');
  const existingDates = new Set(existing.map(r => r.date));

  const insert = db.prepare(`
    INSERT INTO attendance (employee_id, date, hours, note, updated_by, updated_at)
    VALUES (?, ?, 8, NULL, ?, datetime('now'))
    ON CONFLICT(employee_id, date) DO UPDATE SET
      hours = excluded.hours, note = NULL, updated_by = excluded.updated_by, updated_at = datetime('now')
  `);

  let filled = 0;
  for (let d = 1; d <= daysInMonth; d++) {
    if (isWeekend(year, mon, d)) continue;
    const dateStr = `${month}-${String(d).padStart(2, '0')}`;
    if (!overwrite && existingDates.has(dateStr)) continue;
    insert.run(employee_id, dateStr, req.session.user.username);
    filled++;
  }
  res.json({ ok: true, filled });
});

// Сводка по всем сотрудникам организации за месяц — с расчётом скорректированной ЗП
app.get('/api/attendance/summary', requireAuth, (req, res) => {
  const { organization_id, month } = req.query; // month: 'YYYY-MM'
  if (!organization_id || !month) return res.status(400).json({ error: 'Обязательны: organization_id, month' });
  const [year, mon] = month.split('-').map(Number);
  const workdays = countWorkdaysInMonth(year, mon);
  const standardHours = workdays * 8;

  const employees = db.prepare(`
    SELECT * FROM employees WHERE organization_id = ? AND status != 'terminated' ORDER BY full_name
  `).all(organization_id);

  const summary = employees.map(emp => {
    const rows = db.prepare(`SELECT hours FROM attendance WHERE employee_id = ? AND date LIKE ?`).all(emp.id, month + '-%');
    const totalHours = rows.reduce((s, r) => s + (r.hours || 0), 0);
    const hourlyRate = standardHours > 0 ? (emp.official_salary || 0) / standardHours : 0;
    const adjustment = (totalHours - standardHours) * hourlyRate;
    const adjustedSalary = (emp.official_salary || 0) + adjustment;

    const bonusesTotal = db.prepare(`
      SELECT COALESCE(SUM(amount), 0) AS total FROM payroll_adjustments WHERE employee_id = ? AND type = 'bonus' AND date LIKE ?
    `).get(emp.id, month + '-%').total;
    const penaltiesTotal = db.prepare(`
      SELECT COALESCE(SUM(amount), 0) AS total FROM payroll_adjustments WHERE employee_id = ? AND type = 'penalty' AND date LIKE ?
    `).get(emp.id, month + '-%').total;

    const grandTotal = adjustedSalary + (emp.unofficial_salary || 0) + bonusesTotal - penaltiesTotal;

    return {
      employee_id: emp.id,
      full_name: emp.full_name,
      position: emp.position,
      department: emp.department,
      status: emp.status,
      official_salary: emp.official_salary || 0,
      unofficial_salary: emp.unofficial_salary || 0,
      totalHours,
      standardHours,
      hourlyRate: Math.round(hourlyRate * 100) / 100,
      adjustment: Math.round(adjustment),
      adjustedSalary: Math.round(adjustedSalary),
      bonusesTotal: Math.round(bonusesTotal),
      penaltiesTotal: Math.round(penaltiesTotal),
      grandTotal: Math.round(grandTotal),
      daysFilled: rows.length
    };
  });

  res.json({ workdays, standardHours, employees: summary });
});

// ==================== ЗАКАЗЧИКИ И ПРОДАВЦЫ ====================
// Общая таблица контрагентов, различаются полем type: 'customer' (Заказчик) / 'supplier' (Продавец).
// Просмотр и скачивание — всем ролям. Добавление/редактирование/удаление — только
// Владельцу, Главному Бухгалтеру и должностям с его правами (ОД, ДК).

app.get('/api/counterparties', requireAuth, (req, res) => {
  const { organization_id, type } = req.query;
  if (!organization_id || !type) return res.status(400).json({ error: 'Обязательны: organization_id, type' });
  if (!['customer', 'supplier'].includes(type)) return res.status(400).json({ error: 'type должен быть customer или supplier' });
  const rows = db.prepare(`
    SELECT * FROM counterparties WHERE organization_id = ? AND type = ? ORDER BY name
  `).all(organization_id, type);
  res.json(rows);
});

app.post('/api/counterparties', requireEditor, (req, res) => {
  const { organization_id, type, legal_form, name, inn, contact_person, phone, email, address, comment } = req.body;
  if (!organization_id || !type || !name) return res.status(400).json({ error: 'Обязательны: organization_id, type, name' });
  if (!['customer', 'supplier'].includes(type)) return res.status(400).json({ error: 'type должен быть customer или supplier' });
  const info = db.prepare(`
    INSERT INTO counterparties (organization_id, type, legal_form, name, inn, contact_person, phone, email, address, comment, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(organization_id, type, legal_form || null, name.trim(), inn || null, contact_person || null, phone || null, email || null, address || null, comment || null, req.session.user.username);
  logAudit('create', 'counterparties', info.lastInsertRowid, req.session.user.username, req.body);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/counterparties/:id', requireEditor, (req, res) => {
  const { legal_form, name, inn, contact_person, phone, email, address, comment } = req.body;
  const existing = db.prepare('SELECT * FROM counterparties WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Запись не найдена' });
  db.prepare(`
    UPDATE counterparties SET legal_form = ?, name = ?, inn = ?, contact_person = ?, phone = ?, email = ?, address = ?, comment = ?
    WHERE id = ?
  `).run(
    legal_form ?? existing.legal_form, name ?? existing.name, inn ?? existing.inn, contact_person ?? existing.contact_person,
    phone ?? existing.phone, email ?? existing.email, address ?? existing.address, comment ?? existing.comment,
    req.params.id
  );
  logAudit('update', 'counterparties', req.params.id, req.session.user.username, req.body);
  res.json({ ok: true });
});

app.delete('/api/counterparties/:id', requireEditor, (req, res) => {
  db.prepare('DELETE FROM counterparties WHERE id = ?').run(req.params.id);
  db.prepare('DELETE FROM counterparty_contacts WHERE counterparty_id = ?').run(req.params.id);
  logAudit('delete', 'counterparties', req.params.id, req.session.user.username);
  res.json({ ok: true });
});

// ---- Дополнительные контакты заказчика/продавца (несколько человек на одну компанию) ----

app.get('/api/counterparty-contacts', requireAuth, (req, res) => {
  const { counterparty_id } = req.query;
  if (!counterparty_id) return res.status(400).json({ error: 'Обязателен counterparty_id' });
  const rows = db.prepare(`
    SELECT * FROM counterparty_contacts WHERE counterparty_id = ? ORDER BY id
  `).all(counterparty_id);
  res.json(rows);
});

app.post('/api/counterparty-contacts', requireEditor, (req, res) => {
  const { counterparty_id, name, position, phone, email, comment } = req.body;
  if (!counterparty_id || !name) return res.status(400).json({ error: 'Обязательны: counterparty_id, name' });
  const info = db.prepare(`
    INSERT INTO counterparty_contacts (counterparty_id, name, position, phone, email, comment, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(counterparty_id, name.trim(), position || null, phone || null, email || null, comment || null, req.session.user.username);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/counterparty-contacts/:id', requireEditor, (req, res) => {
  const { name, position, phone, email, comment } = req.body;
  const existing = db.prepare('SELECT * FROM counterparty_contacts WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Контакт не найден' });
  db.prepare(`
    UPDATE counterparty_contacts SET name = ?, position = ?, phone = ?, email = ?, comment = ? WHERE id = ?
  `).run(
    name ?? existing.name, position ?? existing.position, phone ?? existing.phone,
    email ?? existing.email, comment ?? existing.comment, req.params.id
  );
  res.json({ ok: true });
});

app.delete('/api/counterparty-contacts/:id', requireEditor, (req, res) => {
  db.prepare('DELETE FROM counterparty_contacts WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ==================== ПРЕМИИ И ШТРАФЫ ====================
// Общая таблица payroll_adjustments, различаются полем type: 'bonus' (Премия) / 'penalty' (Штраф).
// Привязаны к конкретному сотруднику. Просмотр — всем ролям, редактирование —
// только Владельцу, Главному Бухгалтеру, ОД, ДК.

app.get('/api/payroll-adjustments', requireAuth, (req, res) => {
  const { organization_id, type } = req.query;
  if (!organization_id || !type) return res.status(400).json({ error: 'Обязательны: organization_id, type' });
  if (!['bonus', 'penalty'].includes(type)) return res.status(400).json({ error: 'type должен быть bonus или penalty' });
  const rows = db.prepare(`
    SELECT pa.*, e.full_name FROM payroll_adjustments pa
    JOIN employees e ON e.id = pa.employee_id
    WHERE e.organization_id = ? AND pa.type = ?
    ORDER BY pa.date DESC, pa.id DESC
  `).all(organization_id, type);
  res.json(rows);
});

app.post('/api/payroll-adjustments', requireEditor, (req, res) => {
  const { employee_id, type, date, amount, reason, comment } = req.body;
  if (!employee_id || !type || !date || !amount) return res.status(400).json({ error: 'Обязательны: employee_id, type, date, amount' });
  if (!['bonus', 'penalty'].includes(type)) return res.status(400).json({ error: 'type должен быть bonus или penalty' });
  const info = db.prepare(`
    INSERT INTO payroll_adjustments (employee_id, type, date, amount, reason, comment, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(employee_id, type, date, Number(amount) || 0, reason || null, comment || null, req.session.user.username);

  const emp = db.prepare('SELECT full_name FROM employees WHERE id = ?').get(employee_id);
  const label = type === 'bonus' ? 'Премия' : 'Штраф';
  const emoji = type === 'bonus' ? '🏆' : '⚠️';
  let msg = `${emoji} *${label} начислен${type === 'bonus' ? 'а' : ''}*\n━━━━━━━━━━━━━━━━━━\n`;
  if (emp) msg += `👤 Сотрудник: ${emp.full_name}\n`;
  if (reason) msg += `📋 Причина: ${reason}\n`;
  msg += `💰 Сумма: ${fmt(Number(amount) || 0)}\n`;
  msg += `Внёс: ${req.session.user.username}`;
  sendTelegramMessage(msg);

  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/payroll-adjustments/:id', requireEditor, (req, res) => {
  const { date, amount, reason, comment } = req.body;
  const existing = db.prepare('SELECT * FROM payroll_adjustments WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Запись не найдена' });
  db.prepare(`
    UPDATE payroll_adjustments SET date = ?, amount = ?, reason = ?, comment = ? WHERE id = ?
  `).run(
    date ?? existing.date, amount !== undefined ? (Number(amount) || 0) : existing.amount,
    reason ?? existing.reason, comment ?? existing.comment, req.params.id
  );
  res.json({ ok: true });
});

app.delete('/api/payroll-adjustments/:id', requireEditor, (req, res) => {
  db.prepare('DELETE FROM payroll_adjustments WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ==================== ДОПОЛНИТЕЛЬНЫЙ СОЦ. ПАКЕТ ====================
// Общий справочник дополнительных выплат по компании (например "Содержание собаки" — 1000 ₽,
// комментарий "взял на обеспечение"). Не привязан к конкретному сотруднику.
// Доступен всем ролям на просмотр; добавление/редактирование/удаление — только
// Владельцу, Главному Бухгалтеру и должностям с его правами (ОД, ДК).

app.get('/api/social-package', requireAuth, (req, res) => {
  const { month } = req.query; // month: 'YYYY-MM' (необязательно)
  let query = `SELECT * FROM social_package`;
  const params = [];
  if (month) { query += ' WHERE date LIKE ?'; params.push(month + '-%'); }
  query += ' ORDER BY date DESC, id DESC';
  res.json(db.prepare(query).all(...params));
});

app.post('/api/social-package', requireEditor, (req, res) => {
  const { organization_id, date, reason, amount, comment } = req.body;
  if (!date || !amount) return res.status(400).json({ error: 'Обязательны: date, amount' });
  const info = db.prepare(`
    INSERT INTO social_package (organization_id, date, reason, amount, comment, created_by)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(organization_id || null, date, reason || null, Number(amount) || 0, comment || null, req.session.user.username);

  let msg = `🎁 *Доп. соц. пакет — новая запись*\n━━━━━━━━━━━━━━━━━━\n`;
  if (reason) msg += `📋 Причина: ${reason}\n`;
  msg += `💰 Сумма: ${fmt(Number(amount) || 0)}\n`;
  msg += `Внёс: ${req.session.user.username}`;
  sendTelegramMessage(msg);

  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/social-package/:id', requireEditor, (req, res) => {
  const { date, reason, amount, comment } = req.body;
  const existing = db.prepare('SELECT * FROM social_package WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Запись не найдена' });
  db.prepare(`
    UPDATE social_package SET date = ?, reason = ?, amount = ?, comment = ? WHERE id = ?
  `).run(
    date ?? existing.date, reason ?? existing.reason,
    amount !== undefined ? (Number(amount) || 0) : existing.amount,
    comment ?? existing.comment, req.params.id
  );
  res.json({ ok: true });
});

app.delete('/api/social-package/:id', requireEditor, (req, res) => {
  db.prepare('DELETE FROM social_package WHERE id = ?').run(req.params.id);
  res.json({ ok: true });
});

// ==================== БАНКОВСКИЕ СЧЕТА ====================

app.get('/api/bank-accounts', requireAuth, (req, res) => {
  const { organization_id } = req.query;
  if (!organization_id) return res.status(400).json({ error: 'Обязателен organization_id' });
  const rows = db.prepare('SELECT * FROM bank_accounts WHERE organization_id = ? ORDER BY id').all(organization_id);
  res.json(rows);
});

app.post('/api/bank-accounts', requireEditor, (req, res) => {
  const { organization_id, bank_name, bik, account_number, corr_account } = req.body;
  if (!organization_id || !bank_name) return res.status(400).json({ error: 'Обязательны: organization_id, bank_name' });
  const info = db.prepare(`
    INSERT INTO bank_accounts (organization_id, bank_name, bik, account_number, corr_account)
    VALUES (?, ?, ?, ?, ?)
  `).run(organization_id, bank_name, bik || null, account_number || null, corr_account || null);
  logAudit('create', 'bank_accounts', info.lastInsertRowid, req.session.user.username, req.body);
  res.json({ ok: true, id: info.lastInsertRowid });
});

app.put('/api/bank-accounts/:id', requireEditor, (req, res) => {
  const { bank_name, bik, account_number, corr_account } = req.body;
  const existing = db.prepare('SELECT * FROM bank_accounts WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Счёт не найден' });
  db.prepare(`
    UPDATE bank_accounts SET bank_name = ?, bik = ?, account_number = ?, corr_account = ? WHERE id = ?
  `).run(
    bank_name ?? existing.bank_name, bik ?? existing.bik,
    account_number ?? existing.account_number, corr_account ?? existing.corr_account,
    req.params.id
  );
  logAudit('update', 'bank_accounts', req.params.id, req.session.user.username, req.body);
  res.json({ ok: true });
});

app.delete('/api/bank-accounts/:id', requireEditor, (req, res) => {
  db.prepare('DELETE FROM bank_accounts WHERE id = ?').run(req.params.id);
  logAudit('delete', 'bank_accounts', req.params.id, req.session.user.username);
  res.json({ ok: true });
});

// ==================== КАЛЕНДАРЬ ОТЧЁТНОСТИ (типовые статутные сроки) ====================
// ВАЖНО: даты — типовые сроки из НК РФ (28-е/25-е число и т.д.). Могут
// сдвигаться при попадании на выходной ("перенос сроков") и меняться
// законодательно. Проверяйте на nalog.ru или с бухгалтером.

function buildDeadlineTemplates(legalForm, regime) {
  const isOOO = legalForm === 'ООО';
  const items = [];

  if (regime === 'УСН 6% (доходы)' || regime === 'УСН 15% (доходы минус расходы)') {
    items.push({ month: 4, day: 28, title: 'Авансовый платёж УСН за I квартал', type: 'payment' });
    items.push({ month: 7, day: 28, title: 'Авансовый платёж УСН за полугодие', type: 'payment' });
    items.push({ month: 10, day: 28, title: 'Авансовый платёж УСН за 9 месяцев', type: 'payment' });
    if (isOOO) {
      items.push({ month: 3, day: 25, title: 'Декларация по УСН за год', type: 'report' });
      items.push({ month: 3, day: 28, title: 'Итоговый платёж по УСН за год', type: 'payment' });
    } else {
      items.push({ month: 4, day: 25, title: 'Декларация по УСН за год', type: 'report' });
      items.push({ month: 4, day: 28, title: 'Итоговый платёж по УСН за год', type: 'payment' });
    }
  } else if (regime === 'ЕСХН') {
    items.push({ month: 7, day: 28, title: 'Авансовый платёж ЕСХН за полугодие', type: 'payment' });
    items.push({ month: 3, day: 25, title: 'Декларация по ЕСХН за год', type: 'report' });
    items.push({ month: 3, day: 31, title: 'Итоговый платёж по ЕСХН за год', type: 'payment' });
  } else if (regime === 'ПСН (патент)') {
    items.push({ month: null, day: null, title: 'Оплата патента — сроки зависят от даты выдачи и срока патента (декларация не подаётся). Проверьте в личном кабинете налогоплательщика.', type: 'note' });
  } else if (regime === 'ОСНО') {
    // НДС — поквартально, по 1/3 суммы 28 числа каждого из 3 месяцев после квартала
    const vatQuarters = [
      { declMonth: 4, declDay: 25, label: 'I квартал', payMonths: [4, 5, 6] },
      { declMonth: 7, declDay: 25, label: 'II квартал', payMonths: [7, 8, 9] },
      { declMonth: 10, declDay: 25, label: 'III квартал', payMonths: [10, 11, 12] },
      { declMonth: 1, declDay: 25, label: 'IV квартал (пред. года)', payMonths: [1, 2, 3] }
    ];
    vatQuarters.forEach(q => {
      items.push({ month: q.declMonth, day: q.declDay, title: `Декларация по НДС за ${q.label}`, type: 'report' });
      q.payMonths.forEach((m, i) => {
        items.push({ month: m, day: 28, title: `Платёж НДС за ${q.label} (${i + 1}/3)`, type: 'payment' });
      });
    });
    if (isOOO) {
      items.push({ month: 3, day: 25, title: 'Декларация по налогу на прибыль за год', type: 'report' });
      items.push({ month: 3, day: 28, title: 'Итоговый платёж по налогу на прибыль за год', type: 'payment' });
      items.push({ month: 4, day: 28, title: 'Авансовый платёж по налогу на прибыль за I квартал', type: 'payment' });
      items.push({ month: 7, day: 28, title: 'Авансовый платёж по налогу на прибыль за полугодие', type: 'payment' });
      items.push({ month: 10, day: 28, title: 'Авансовый платёж по налогу на прибыль за 9 месяцев', type: 'payment' });
    } else {
      items.push({ month: 4, day: 30, title: 'Декларация 3-НДФЛ за год', type: 'report' });
      items.push({ month: 7, day: 15, title: 'Уплата НДФЛ по итогам года', type: 'payment' });
      items.push({ month: 4, day: 25, title: 'Авансовый платёж НДФЛ за I квартал', type: 'payment' });
      items.push({ month: 7, day: 25, title: 'Авансовый платёж НДФЛ за полугодие', type: 'payment' });
      items.push({ month: 10, day: 25, title: 'Авансовый платёж НДФЛ за 9 месяцев', type: 'payment' });
    }
  }

  return items;
}

function nextOccurrence(month, day, fromDate) {
  const year = fromDate.getFullYear();
  let d = new Date(year, month - 1, day);
  d.setHours(0, 0, 0, 0);
  if (d < fromDate) d = new Date(year + 1, month - 1, day);
  return d;
}

app.get('/api/tax-calendar', requireAuth, (req, res) => {
  const { organization_id } = req.query;
  if (!organization_id) return res.status(400).json({ error: 'Обязателен organization_id' });
  const org = db.prepare('SELECT * FROM organizations WHERE id = ?').get(organization_id);
  if (!org) return res.status(404).json({ error: 'Организация не найдена' });

  const today = new Date();
  today.setHours(0, 0, 0, 0);
  const templates = buildDeadlineTemplates(org.legal_form, org.tax_regime);

  const items = templates.map(t => {
    if (t.month === null) {
      return { date: null, title: t.title, type: t.type, daysUntil: null };
    }
    const date = nextOccurrence(t.month, t.day, today);
    const daysUntil = Math.round((date - today) / 86400000);
    return {
      date: date.toISOString().slice(0, 10),
      title: t.title,
      type: t.type,
      daysUntil
    };
  });

  items.sort((a, b) => {
    if (a.date === null) return 1;
    if (b.date === null) return -1;
    return new Date(a.date) - new Date(b.date);
  });

  res.json({
    regime: org.tax_regime,
    legalForm: org.legal_form,
    items: items.slice(0, 8),
    disclaimer: 'Типовые статутные сроки из НК РФ. Могут сдвигаться при переносе на выходные дни и меняться законодательно — сверяйте на nalog.ru или с бухгалтером.'
  });
});

app.get('/api/tax-estimate', requireAuth, (req, res) => {
  const { organization_id, from, to } = req.query;
  if (!organization_id || !from || !to) {
    return res.status(400).json({ error: 'Обязательны: organization_id, from, to' });
  }
  const org = db.prepare('SELECT * FROM organizations WHERE id = ?').get(organization_id);
  if (!org) return res.status(404).json({ error: 'Организация не найдена' });

  const income = db.prepare(`
    SELECT COALESCE(SUM(amount),0) AS s FROM transactions
    WHERE organization_id = ? AND type = 'income' AND date BETWEEN ? AND ?
  `).get(organization_id, from, to).s;
  const expense = db.prepare(`
    SELECT COALESCE(SUM(amount),0) AS s FROM transactions
    WHERE organization_id = ? AND type = 'expense' AND date BETWEEN ? AND ?
  `).get(organization_id, from, to).s;

  let result = { regime: org.tax_regime, income, expense, taxEstimate: 0, explanation: '', disclaimer:
    'Ориентировочный расчёт для планирования. Не является официальной декларацией — сверяйте с бухгалтером/налоговым консультантом.' };

  const daysInRange = (new Date(to) - new Date(from)) / 86400000 + 1;
  const monthsInRange = Math.max(1, Math.round(daysInRange / 30.44));

  switch (org.tax_regime) {
    case 'УСН 6% (доходы)': {
      const rate = org.tax_rate || 6;
      result.taxEstimate = income * (rate / 100);
      result.explanation = `${rate}% от дохода (${fmt(income)}). Расходы на расчёт не влияют.`;
      break;
    }
    case 'УСН 15% (доходы минус расходы)': {
      const rate = org.tax_rate || 15;
      const base = Math.max(0, income - expense);
      const calcTax = base * (rate / 100);
      const minTax = income * 0.01;
      result.taxEstimate = income > 0 ? Math.max(calcTax, minTax) : 0;
      result.explanation = `${rate}% от (доход − расход) = ${rate}% от ${fmt(base)}. ` +
        (result.taxEstimate === minTax && minTax > calcTax
          ? `Применён минимальный налог 1% от дохода (${fmt(minTax)}), т.к. он выше расчётного.`
          : `Расчётный налог: ${fmt(calcTax)}.`);
      break;
    }
    case 'ЕСХН': {
      const rate = org.tax_rate || 6;
      const base = Math.max(0, income - expense);
      result.taxEstimate = base * (rate / 100);
      result.explanation = `${rate}% от (доход − расход) = ${rate}% от ${fmt(base)}.`;
      break;
    }
    case 'ПСН (патент)': {
      const yearly = org.patent_cost_yearly || 0;
      result.taxEstimate = (yearly / 12) * monthsInRange;
      result.explanation = yearly
        ? `Фиксированная стоимость патента ${fmt(yearly)}/год, за период ~${monthsInRange} мес.: ${fmt(result.taxEstimate)}. Не зависит от реального дохода.`
        : `Стоимость патента не указана в настройках организации — укажите её, чтобы увидеть расчёт.`;
      break;
    }
    case 'ОСНО': {
      const base = Math.max(0, income - expense);
      if (org.legal_form === 'ООО') {
        const profitTaxRate = 25; // налог на прибыль для ООО, ставка 2026 года
        const vatRate = 22;       // НДС, ставка 2026 года
        const profitTax = base * (profitTaxRate / 100);
        result.taxEstimate = profitTax;
        result.explanation = `Налог на прибыль (${profitTaxRate}% в 2026 году, для ООО) от (доход − расход) = ` +
          `${profitTaxRate}% от ${fmt(base)} = ${fmt(profitTax)}. ` +
          `Дополнительно начисляется НДС (${vatRate}% в 2026 году) на реализацию — он обычно уменьшается на ` +
          `входящий НДС по закупкам и здесь не включён в сумму, так как требует полного учёта счетов-фактур.`;
      } else {
        result.taxEstimate = null;
        result.explanation = 'Для ИП на ОСНО применяется НДФЛ (13-15% в зависимости от суммы дохода) вместо ' +
          'налога на прибыль, а также НДС (22% в 2026 году) по общим правилам. Точный расчёт требует ' +
          'профессионального бухгалтерского учёта — этот дашборд показывает только доход/расход/прибыль ' +
          'для ОСНО (ИП) без оценки налога.';
      }
      break;
    }
    default:
      result.explanation = 'Неизвестный налоговый режим.';
  }

  res.json(result);
});



// Список всех транзакций (для дашборда), опционально фильтр по организации
app.get('/api/transactions', requireAuth, (req, res) => {
  const { organization_id } = req.query;
  const rows = organization_id
    ? db.prepare('SELECT * FROM transactions WHERE organization_id = ? ORDER BY date DESC, id DESC').all(organization_id)
    : db.prepare('SELECT * FROM transactions ORDER BY date DESC, id DESC').all();
  res.json(rows);
});

// Добавление новой транзакции (бухгалтер или владелец)
app.post('/api/transactions', requireAuth, async (req, res) => {
  const {
    date, type, category, amount, description, status, responsible, organization_id,
    employee_id, payroll_type, payroll_period
  } = req.body;
  if (!date || !category || !amount) {
    return res.status(400).json({ error: 'Обязательны: date, category, amount' });
  }
  const orgId = organization_id || 1;
  const org = db.prepare('SELECT name FROM organizations WHERE id = ?').get(orgId);
  const txType = type === 'income' ? 'income' : 'expense';

  const info = db.prepare(`
    INSERT INTO transactions
      (organization_id, date, type, category, amount, description, status, responsible,
       employee_id, payroll_type, payroll_period, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(orgId, date, txType, category, Number(amount), description || '', status || 'Оплачено',
         responsible || req.session.user.username,
         employee_id || null, payroll_type || null, payroll_period || null,
         req.session.user.username);

  logAudit('create', 'transactions', info.lastInsertRowid, req.session.user.username, req.body);

  // ---- Telegram-уведомление ----
  const monthPrefix = date.slice(0, 7); // YYYY-MM
  const todayTotal = db.prepare(`
    SELECT COALESCE(SUM(amount),0) AS total FROM transactions WHERE date = ? AND type = ? AND organization_id = ?
  `).get(date, txType, orgId).total;
  const monthTotal = db.prepare(`
    SELECT COALESCE(SUM(amount),0) AS total FROM transactions
    WHERE category = ? AND date LIKE ? AND type = ? AND organization_id = ?
  `).get(category, monthPrefix + '%', txType, orgId).total;
  const limitRow = txType === 'expense'
    ? db.prepare('SELECT monthly_limit FROM budget_limits WHERE category = ? AND organization_id = ?').get(category, orgId)
    : null;
  const limit = limitRow ? limitRow.monthly_limit : null;
  const pct = limit ? Math.round((monthTotal / limit) * 100) : null;
  const flag = pct === null ? '' : pct >= 100 ? '🔴' : pct >= 80 ? '🟡' : '🟢';

  const isIncome = txType === 'income';
  let msg = (isIncome ? '📈 *Новый доход*\n' : '💰 *Новая запись в финансах*\n') + '━━━━━━━━━━━━━━━━━━\n';
  if (org) msg += `🏢 Организация: ${org.name}\n`;
  msg += `📅 Дата операции: ${date}\n🕐 Внесено: ${nowMoscow()} (МСК)\n🏷️ Категория: ${category}\n💵 Сумма: ${fmt(amount)}\n`;
  if (employee_id) {
    const emp = db.prepare('SELECT full_name FROM employees WHERE id = ?').get(employee_id);
    if (emp) msg += `👤 Сотрудник: ${emp.full_name}\n`;
  }
  if (payroll_type) msg += `📋 Тип выплаты: ${payroll_type}\n`;
  if (payroll_period) msg += `📆 Период: ${payroll_period}\n`;
  if (description) msg += `📝 Описание: ${description}\n`;
  msg += `👤 Внёс: ${responsible || req.session.user.username}\n`;
  msg += `━━━━━━━━━━━━━━━━━━\n📈 Итого за день (${isIncome ? 'доход' : 'расход'}): ${fmt(todayTotal)}\n`;
  if (limit) msg += `${flag} «${category}» за месяц: ${fmt(monthTotal)} из ${fmt(limit)} (${pct}%)`;

  sendTelegramMessage(msg);

  res.json({ ok: true, id: info.lastInsertRowid });
});

// Массовый импорт транзакций (например, из CSV)
app.post('/api/transactions/import', requireAuth, async (req, res) => {
  const { rows, organization_id } = req.body;
  if (!Array.isArray(rows) || !rows.length) {
    return res.status(400).json({ error: 'Нет данных для импорта' });
  }
  const orgId = organization_id || 1;

  const insert = db.prepare(`
    INSERT INTO transactions (organization_id, date, type, category, amount, description, status, responsible, created_by)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  let imported = 0;
  let skipped = 0;
  const tx = db.transaction((items) => {
    for (const r of items) {
      if (!r.date || !r.category || !r.amount) { skipped++; continue; }
      const txType = r.type === 'income' ? 'income' : 'expense';
      insert.run(
        orgId, r.date, txType, r.category, Number(r.amount),
        r.description || '', r.status || 'Оплачено',
        r.responsible || req.session.user.username,
        req.session.user.username
      );
      imported++;
    }
  });
  tx(rows);

  logAudit('import', 'transactions', null, req.session.user.username, { imported, skipped });

  sendTelegramMessage(
    `📥 *Импорт CSV завершён*\n━━━━━━━━━━━━━━━━━━\n` +
    `🕐 Время (МСК): ${nowMoscow()}\n` +
    `Импортировано записей: ${imported}\n` +
    (skipped ? `Пропущено (неполные данные): ${skipped}\n` : '') +
    `Выполнил: ${req.session.user.username}`
  );

  res.json({ ok: true, imported, skipped });
});

// Удаление записи (только владелец)
app.delete('/api/transactions/:id', requireAuth, (req, res) => {
  db.prepare('DELETE FROM transactions WHERE id = ?').run(req.params.id);
  logAudit('delete', 'transactions', req.params.id, req.session.user.username);
  res.json({ ok: true });
});

app.put('/api/transactions/:id', requireAuth, (req, res) => {
  const existing = db.prepare('SELECT * FROM transactions WHERE id = ?').get(req.params.id);
  if (!existing) return res.status(404).json({ error: 'Запись не найдена' });

  const {
    date, type, category, amount, description, status, responsible, organization_id,
    employee_id, payroll_type, payroll_period
  } = req.body;

  db.prepare(`
    UPDATE transactions SET
      date = ?, type = ?, category = ?, amount = ?, description = ?, status = ?, responsible = ?,
      organization_id = ?, employee_id = ?, payroll_type = ?, payroll_period = ?
    WHERE id = ?
  `).run(
    date ?? existing.date,
    type === 'income' || type === 'expense' ? type : existing.type,
    category ?? existing.category,
    amount !== undefined ? Number(amount) : existing.amount,
    description ?? existing.description,
    status ?? existing.status,
    responsible ?? existing.responsible,
    organization_id ?? existing.organization_id,
    employee_id !== undefined ? (employee_id || null) : existing.employee_id,
    payroll_type !== undefined ? (payroll_type || null) : existing.payroll_type,
    payroll_period !== undefined ? (payroll_period || null) : existing.payroll_period,
    req.params.id
  );

  logAudit('update', 'transactions', req.params.id, req.session.user.username, req.body);
  res.json({ ok: true });
});

// ==================== ЛИМИТЫ БЮДЖЕТА ====================

app.get('/api/budget-limits', requireAuth, (req, res) => {
  const { organization_id } = req.query;
  if (!organization_id) return res.status(400).json({ error: 'Обязателен параметр organization_id' });
  const rows = db.prepare('SELECT * FROM budget_limits WHERE organization_id = ?').all(organization_id);
  res.json(rows);
});

app.put('/api/budget-limits', requireOwner, (req, res) => {
  const { organization_id, limits } = req.body; // { organization_id, limits: { "Категория": число, ... } }
  if (!organization_id || !limits) return res.status(400).json({ error: 'Обязательны: organization_id, limits' });
  const upsert = db.prepare(`
    INSERT INTO budget_limits (organization_id, category, monthly_limit) VALUES (?, ?, ?)
    ON CONFLICT(organization_id, category) DO UPDATE SET monthly_limit = excluded.monthly_limit
  `);
  const tx = db.transaction((entries) => {
    for (const [cat, limit] of entries) upsert.run(organization_id, cat, Number(limit) || 0);
  });
  tx(Object.entries(limits));
  logAudit('update', 'budget_limits', organization_id, req.session.user.username, limits);
  res.json({ ok: true });
});

// ==================== СВОДКА (для дашборда) ====================

app.get('/api/summary', requireAuth, (req, res) => {
  const now = new Date();
  const monthPrefix = now.toISOString().slice(0, 7);
  const monthRows = db.prepare('SELECT * FROM transactions WHERE date LIKE ?').all(monthPrefix + '%');
  const limits = db.prepare('SELECT * FROM budget_limits').all();
  res.json({ monthTransactions: monthRows, budgetLimits: limits });
});

// ==================== ПРАВИЛА ДОСТУПА (RULES.md) ====================
// Отдаём содержимое файла RULES.md как есть — то же самое, что видит владелец,
// открыв файл напрямую. Один источник правды, расхождений быть не может.

app.get('/api/rules', requireAuth, (req, res) => {
  try {
    const content = fs.readFileSync(path.join(__dirname, 'RULES.md'), 'utf-8');
    res.json({ markdown: content });
  } catch (err) {
    res.status(404).json({ error: 'Файл RULES.md не найден на сервере' });
  }
});

// ==================== АУДИТ (только владелец) ====================

app.get('/api/audit-log', requireOwner, (req, res) => {
  const rows = db.prepare('SELECT * FROM audit_log ORDER BY id DESC LIMIT 200').all();
  res.json(rows);
});

// ==================== ОБРАБОТКА ОШИБОК ЗАГРУЗКИ ФАЙЛОВ ====================

app.use((err, req, res, next) => {
  if (err instanceof multer.MulterError) {
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(413).json({ error: 'Файл слишком большой — максимум 150 МБ' });
    }
    return res.status(400).json({ error: 'Ошибка загрузки файла: ' + err.message });
  }
  next(err);
});

// ==================== ЗАПУСК ====================

// ==================== НАПОМИНАНИЯ О ВЫПЛАТЕ ЗП/АВАНСА ====================
// Правило: ЗП — 10 числа, Аванс — 25 числа. Если дата выпадает на выходной (Сб/Вс),
// выплата переносится на ближайший предыдущий рабочий день (канун). За 2 дня до
// фактической (перенесённой) даты выплаты — уведомление Бухгалтеру и Обычным
// пользователям (Делопроизводителю) в личный Telegram + в общий чат.
// ВАЖНО: официальные праздники РФ не учитываются (нет производственного календаря),
// учитываются только выходные Сб/Вс.

function getAdjustedPayDate(year, month, day) {
  const d = new Date(year, month - 1, day);
  const dow = d.getDay(); // 0=вс, 6=сб
  if (dow === 0) d.setDate(d.getDate() - 2); // воскресенье → пятница
  else if (dow === 6) d.setDate(d.getDate() - 1); // суббота → пятница
  return d;
}

function checkSalaryReminders() {
  try {
    const now = new Date();
    const todayStr = now.toISOString().slice(0, 10);
    const targets = [
      { day: 10, label: 'Зарплата (10 число)' },
      { day: 25, label: 'Аванс (25 число)' }
    ];

    targets.forEach(t => {
      // Проверяем и текущий, и следующий месяц — на случай, если перенос на канун
      // сдвигает дату так, что "за 2 дня" приходится уже на предыдущий календарный месяц.
      [0, 1].forEach(monthOffset => {
        const targetDate = new Date(now.getFullYear(), now.getMonth() + monthOffset, t.day);
        const payDate = getAdjustedPayDate(targetDate.getFullYear(), targetDate.getMonth() + 1, t.day);
        const reminderDate = new Date(payDate);
        reminderDate.setDate(reminderDate.getDate() - 2);
        const reminderDateStr = reminderDate.toISOString().slice(0, 10);

        if (reminderDateStr !== todayStr) return;

        const already = db.prepare('SELECT 1 FROM reminders_sent WHERE date = ? AND type = ?').get(todayStr, t.label);
        if (already) return;

        const payDateStr = payDate.toLocaleDateString('ru-RU', { day: '2-digit', month: 'long', year: 'numeric' });
        const wasShifted = payDate.getDate() !== t.day;
        let msg = `🔔 *Напоминание о выплате*\n━━━━━━━━━━━━━━━━━━\n${t.label}\n📅 Дата выплаты: ${payDateStr}`;
        if (wasShifted) msg += ` (перенесено с ${t.day} числа — выходной)`;
        msg += `\n⏰ Осталось 2 дня — подготовьте выплату.`;

        const recipients = db.prepare(`
          SELECT telegram_chat_id FROM users WHERE role IN ('accountant', 'user') AND telegram_chat_id IS NOT NULL
        `).all();
        recipients.forEach(r => sendTelegramMessage(msg, r.telegram_chat_id));
        sendTelegramMessage(msg); // и в общий чат (тот же, что для обычных уведомлений)

        db.prepare('INSERT INTO reminders_sent (date, type) VALUES (?, ?)').run(todayStr, t.label);
        console.log(`✓ Отправлено напоминание: ${t.label}, дата выплаты ${payDateStr}`);
      });
    });
  } catch (err) {
    console.error('Ошибка проверки напоминаний о ЗП:', err.message);
  }
}

setInterval(checkSalaryReminders, 60 * 60 * 1000); // проверяем раз в час
checkSalaryReminders(); // и сразу при старте сервера

app.listen(PORT, () => {
  console.log(`✓ Финансовый сервер запущен: http://localhost:${PORT}`);
  console.log(`  Версия функционала: v3 (организации + налоги + доход/расход + импорт CSV)`);
  console.log(`  Файл server.js изменён: ${require('fs').statSync(__filename).mtime}`);
});
