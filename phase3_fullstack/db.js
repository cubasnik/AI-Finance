// ============================================================
// db.js — инициализация базы данных SQLite
// ============================================================
// Запускается автоматически при старте server.js, либо вручную:
//   npm run init-db
// Создаёт файл finance.db (если его ещё нет) со всеми таблицами
// и учётными записями по умолчанию из .env.
// ============================================================

require('dotenv').config();
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const path = require('path');

const db = new Database(path.join(__dirname, 'finance.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('owner', 'accountant', 'user')),
    full_name TEXT,
    email TEXT,
    phone TEXT,
    telegram_chat_id TEXT,
    telegram_username TEXT,
    position TEXT,
    password_changed_at TEXT DEFAULT (datetime('now')),
    reset_token TEXT,
    reset_token_expires TEXT,
    failed_login_attempts INTEGER DEFAULT 0,
    locked_until TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS organizations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    legal_form TEXT NOT NULL CHECK(legal_form IN ('ООО', 'ИП')),
    inn TEXT,
    kpp TEXT,
    ogrn TEXT,
    legal_address TEXT,
    postal_address TEXT,
    phone TEXT,
    contact_person TEXT,
    tax_regime TEXT NOT NULL DEFAULT 'УСН 6% (доходы)',
    tax_rate REAL,              -- переопределение ставки в % (необязательно, иначе берётся стандартная для региона)
    patent_cost_yearly REAL,    -- стоимость патента в год (только для ПСН)
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS bank_accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    bank_name TEXT NOT NULL,
    bik TEXT,
    account_number TEXT,   -- расчётный счёт
    corr_account TEXT,     -- корреспондентский счёт
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS employees (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    full_name TEXT NOT NULL,
    position TEXT,
    status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'terminated', 'temporary', 'unofficial')),
    official_salary REAL DEFAULT 0,
    unofficial_salary REAL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS attendance (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    date TEXT NOT NULL,             -- YYYY-MM-DD
    hours REAL NOT NULL DEFAULT 8,  -- 8 — стандартный день, 0 — прогул/выходной за свой счёт, >8 — переработка
    note TEXT,                      -- необязательная пометка: "Прогул", "За свой счёт", "Больничный" и т.д.
    updated_by TEXT,
    updated_at TEXT DEFAULT (datetime('now')),
    UNIQUE(employee_id, date)
  );

  CREATE TABLE IF NOT EXISTS social_package (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER,
    employee_id INTEGER,            -- оставлено для совместимости со старыми записями, больше не используется
    date TEXT NOT NULL,             -- YYYY-MM-DD, месяц начисления определяется по ней
    reason TEXT,                    -- причина выплаты (например "Содержание собаки", "Материальная помощь")
    amount REAL NOT NULL DEFAULT 0,
    comment TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS counterparties (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('customer', 'supplier')), -- customer = Заказчик, supplier = Продавец
    legal_form TEXT,       -- ООО / ИП / АО и т.д.
    name TEXT NOT NULL,
    inn TEXT,
    contact_person TEXT,
    phone TEXT,
    email TEXT,
    address TEXT,
    comment TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS counterparty_contacts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    counterparty_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    position TEXT,
    phone TEXT,
    email TEXT,
    comment TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS payroll_adjustments (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    employee_id INTEGER NOT NULL,
    type TEXT NOT NULL CHECK(type IN ('bonus', 'penalty')), -- bonus = Премия, penalty = Штраф
    date TEXT NOT NULL,
    amount REAL NOT NULL DEFAULT 0,
    reason TEXT,
    comment TEXT,
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reminders_sent (
    date TEXT NOT NULL,
    type TEXT NOT NULL,
    PRIMARY KEY (date, type)
  );

  CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    organization_id INTEGER NOT NULL DEFAULT 1,
    date TEXT NOT NULL,               -- YYYY-MM-DD
    type TEXT NOT NULL DEFAULT 'expense', -- 'income' | 'expense'
    category TEXT NOT NULL,
    amount REAL NOT NULL,
    description TEXT,
    status TEXT DEFAULT 'Оплачено',
    responsible TEXT,
    employee_id INTEGER,        -- заполняется для категории "Зарплата"
    payroll_type TEXT,          -- Оклад / Больничный / Отпускные / за свой счёт и т.д.
    payroll_period TEXT,        -- YYYY-MM — за какой месяц начисление
    created_by TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS budget_limits (
    organization_id INTEGER NOT NULL DEFAULT 1,
    category TEXT NOT NULL,
    monthly_limit REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (organization_id, category)
  );

  CREATE TABLE IF NOT EXISTS conversations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK(type IN ('dm', 'group')),
    name TEXT,
    created_by INTEGER,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS conversation_members (
    conversation_id INTEGER NOT NULL,
    user_id INTEGER NOT NULL,
    last_read_message_id INTEGER DEFAULT 0,
    pinned_at TEXT,
    PRIMARY KEY (conversation_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS chat_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    conversation_id INTEGER NOT NULL,
    sender_id INTEGER NOT NULL,
    body TEXT,
    attachment_filename TEXT,
    attachment_path TEXT,
    attachment_mimetype TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    action TEXT NOT NULL,             -- create / update / delete
    entity TEXT NOT NULL,             -- transactions / budget_limits / users
    entity_id TEXT,
    performed_by TEXT,
    details TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

// ---------- Миграция: добавить колонку type, если БД уже существовала ----------
const txCols = db.prepare("PRAGMA table_info(transactions)").all().map(c => c.name);
if (!txCols.includes('type')) {
  db.exec("ALTER TABLE transactions ADD COLUMN type TEXT NOT NULL DEFAULT 'expense'");
  console.log('✓ Миграция: добавлена колонка "type" в transactions (все старые записи помечены как расход)');
}

// ---------- Миграция: добавить колонку organization_id, если БД уже существовала ----------
if (!txCols.includes('organization_id')) {
  db.exec("ALTER TABLE transactions ADD COLUMN organization_id INTEGER NOT NULL DEFAULT 1");
  console.log('✓ Миграция: добавлена колонка "organization_id" в transactions');
}

// ---------- Миграция: контактные данные пользователя (для профиля и справочника коллег) ----------
const userCols = db.prepare("PRAGMA table_info(users)").all().map(c => c.name);
const newUserFields = { full_name: 'TEXT', email: 'TEXT', phone: 'TEXT', telegram_chat_id: 'TEXT', telegram_username: 'TEXT', position: 'TEXT', password_changed_at: 'TEXT', reset_token: 'TEXT', reset_token_expires: 'TEXT', failed_login_attempts: 'INTEGER DEFAULT 0', locked_until: 'TEXT' };
Object.entries(newUserFields).forEach(([col, type]) => {
  if (!userCols.includes(col)) {
    db.exec(`ALTER TABLE users ADD COLUMN ${col} ${type}`);
    console.log(`✓ Миграция: добавлена колонка "${col}" в users`);
  }
});

// Для уже существующих пользователей без даты смены пароля — берём дату
// создания аккаунта (даёт им полный льготный период с этого момента)
db.exec(`UPDATE users SET password_changed_at = created_at WHERE password_changed_at IS NULL`);

// ---------- Миграция: новые статусы сотрудников (temporary, unofficial) ----------
const employeesTableRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='employees'").get();
if (employeesTableRow && !employeesTableRow.sql.includes("'temporary'")) {
  db.exec(`
    CREATE TABLE employees_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER NOT NULL,
      full_name TEXT NOT NULL,
      position TEXT,
      status TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active', 'terminated', 'temporary', 'unofficial')),
      official_salary REAL DEFAULT 0,
      unofficial_salary REAL DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.exec(`
    INSERT INTO employees_new (id, organization_id, full_name, position, status, created_at)
    SELECT id, organization_id, full_name, position, status, created_at FROM employees
  `);
  db.exec('DROP TABLE employees');
  db.exec('ALTER TABLE employees_new RENAME TO employees');
  console.log('✓ Миграция: добавлены статусы "Временный" и "Неофициальный" для сотрудников');
}

// ---------- Миграция: приведение всех сохранённых телефонов к единому формату +7 ХХХ ХХХ-ХХ-ХХ ----------
function formatRuPhoneForMigration(raw) {
  if (!raw) return raw;
  let digits = String(raw).replace(/\D/g, '');
  if (digits.startsWith('7')) digits = digits.slice(1);
  else if (digits.startsWith('8')) digits = digits.slice(1);
  digits = digits.slice(0, 10);
  if (!digits) return raw;
  let out = '+7';
  out += ' ' + digits.slice(0, 3);
  if (digits.length > 3) out += ' ' + digits.slice(3, 6);
  if (digits.length > 6) out += '-' + digits.slice(6, 8);
  if (digits.length > 8) out += '-' + digits.slice(8, 10);
  return out;
}
[
  { table: 'employees', cols: ['phone_work', 'phone_personal'] },
  { table: 'counterparties', cols: ['phone'] },
  { table: 'counterparty_contacts', cols: ['phone'] }
].forEach(({ table, cols }) => {
  const tableExists = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name=?").get(table);
  if (!tableExists) return;
  const rows = db.prepare(`SELECT id, ${cols.join(', ')} FROM ${table}`).all();
  rows.forEach(row => {
    const updates = {};
    let changed = false;
    cols.forEach(col => {
      const formatted = formatRuPhoneForMigration(row[col]);
      if (formatted !== row[col]) { updates[col] = formatted; changed = true; }
    });
    if (changed) {
      const setClause = cols.map(c => `${c} = ?`).join(', ');
      db.prepare(`UPDATE ${table} SET ${setClause} WHERE id = ?`).run(...cols.map(c => updates[c] !== undefined ? updates[c] : row[c]), row.id);
    }
  });
});
console.log('✓ Проверка/приведение телефонов к единому формату +7 ХХХ ХХХ-ХХ-ХХ выполнена');

// ---------- Миграция: соц. пакет — привязка к организации вместо обязательного сотрудника ----------
const socialPackageTableRow = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='social_package'").get();
if (socialPackageTableRow && socialPackageTableRow.sql.includes('employee_id INTEGER NOT NULL')) {
  db.exec(`
    CREATE TABLE social_package_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      organization_id INTEGER,
      employee_id INTEGER,
      date TEXT NOT NULL,
      reason TEXT,
      amount REAL NOT NULL DEFAULT 0,
      comment TEXT,
      created_by TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.exec(`
    INSERT INTO social_package_new (id, employee_id, date, reason, amount, comment, created_by, created_at)
    SELECT id, employee_id, date, reason, amount, comment, created_by, created_at FROM social_package
  `);
  // Проставляем organization_id старым записям по их сотруднику, где это возможно
  db.exec(`
    UPDATE social_package_new
    SET organization_id = (SELECT organization_id FROM employees WHERE employees.id = social_package_new.employee_id)
    WHERE organization_id IS NULL
  `);
  db.exec('DROP TABLE social_package');
  db.exec('ALTER TABLE social_package_new RENAME TO social_package');
  console.log('✓ Миграция: "Доп. соц. пакет" переведён на привязку к организации (справочник, без обязательного сотрудника)');
}

// ---------- Миграция: форма организации (ООО/ИП) у заказчиков/продавцов ----------
const counterpartiesCols = db.prepare("PRAGMA table_info(counterparties)").all().map(c => c.name);
if (counterpartiesCols.length && !counterpartiesCols.includes('legal_form')) {
  db.exec("ALTER TABLE counterparties ADD COLUMN legal_form TEXT");
  console.log('✓ Миграция: добавлена колонка "legal_form" в counterparties');
}

// ---------- Миграция: контактные данные сотрудника (телефоны, почта, Telegram) ----------
const employeeContactCols = db.prepare("PRAGMA table_info(employees)").all().map(c => c.name);
['phone_work', 'phone_personal', 'email_work', 'telegram_username'].forEach(col => {
  if (!employeeContactCols.includes(col)) {
    db.exec(`ALTER TABLE employees ADD COLUMN ${col} TEXT`);
    console.log(`✓ Миграция: добавлена колонка "${col}" в employees`);
  }
});

// ---------- Миграция: подразделение сотрудника (для группировки в табеле) ----------
const employeeCols2 = db.prepare("PRAGMA table_info(employees)").all().map(c => c.name);
if (!employeeCols2.includes('department')) {
  db.exec("ALTER TABLE employees ADD COLUMN department TEXT");
  console.log('✓ Миграция: добавлена колонка "department" в employees');
}

// ---------- Миграция: официальная и неофициальная ЗП (для установок, где статусы уже обновлены, но полей ЗП ещё нет) ----------
const employeeColsCheck = db.prepare("PRAGMA table_info(employees)").all().map(c => c.name);
if (!employeeColsCheck.includes('official_salary')) {
  db.exec("ALTER TABLE employees ADD COLUMN official_salary REAL DEFAULT 0");
  console.log('✓ Миграция: добавлена колонка "official_salary" в employees');
}
if (!employeeColsCheck.includes('unofficial_salary')) {
  db.exec("ALTER TABLE employees ADD COLUMN unofficial_salary REAL DEFAULT 0");
  console.log('✓ Миграция: добавлена колонка "unofficial_salary" в employees');
}

// ---------- Миграция: разрешить роль 'user' (Обычный пользователь) ----------
// SQLite не умеет менять CHECK-ограничение через ALTER TABLE — пересоздаём таблицу.
const usersTableSql = db.prepare("SELECT sql FROM sqlite_master WHERE type='table' AND name='users'").get().sql;
if (!usersTableSql.includes("'user'")) {
  db.exec(`
    CREATE TABLE users_new (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('owner', 'accountant', 'user')),
      full_name TEXT,
      email TEXT,
      phone TEXT,
      telegram_chat_id TEXT,
      telegram_username TEXT,
      position TEXT,
      password_changed_at TEXT DEFAULT (datetime('now')),
      reset_token TEXT,
      reset_token_expires TEXT,
      failed_login_attempts INTEGER DEFAULT 0,
      locked_until TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    )
  `);
  db.exec(`
    INSERT INTO users_new (id, username, password_hash, role, full_name, email, phone, telegram_chat_id,
      telegram_username, position, password_changed_at, reset_token, reset_token_expires,
      failed_login_attempts, locked_until, created_at)
    SELECT id, username, password_hash, role, full_name, email, phone, telegram_chat_id,
      telegram_username, position, password_changed_at, reset_token, reset_token_expires,
      failed_login_attempts, locked_until, created_at
    FROM users
  `);
  db.exec('DROP TABLE users');
  db.exec('ALTER TABLE users_new RENAME TO users');
  console.log('✓ Миграция: роль "Обычный пользователь" (user) добавлена в схему');
}

// ---------- Миграция: реквизиты организации (КПП, ОГРН, адреса, телефон, ФИО) ----------
const orgCols = db.prepare("PRAGMA table_info(organizations)").all().map(c => c.name);
const newOrgFields = {
  kpp: 'TEXT', ogrn: 'TEXT', legal_address: 'TEXT',
  postal_address: 'TEXT', phone: 'TEXT', contact_person: 'TEXT'
};
Object.entries(newOrgFields).forEach(([col, type]) => {
  if (!orgCols.includes(col)) {
    db.exec(`ALTER TABLE organizations ADD COLUMN ${col} ${type}`);
    console.log(`✓ Миграция: добавлена колонка "${col}" в organizations`);
  }
});

// ---------- Организация по умолчанию (если таблица пустая) ----------
const orgCount = db.prepare('SELECT COUNT(*) AS c FROM organizations').get().c;
if (orgCount === 0) {
  db.prepare(`
    INSERT INTO organizations (name, legal_form, tax_regime)
    VALUES (?, ?, ?)
  `).run(process.env.DEFAULT_ORG_NAME || 'Основная организация', 'ООО', 'УСН 6% (доходы)');
  console.log('✓ Создана организация по умолчанию — переименуй её в дашборде под свою компанию');
}

// ---------- Миграция: budget_limits теперь привязаны к организации ----------
const blCols = db.prepare("PRAGMA table_info(budget_limits)").all().map(c => c.name);
if (!blCols.includes('organization_id')) {
  const oldRows = db.prepare('SELECT * FROM budget_limits').all();
  db.exec('ALTER TABLE budget_limits RENAME TO budget_limits_old');
  db.exec(`
    CREATE TABLE budget_limits (
      organization_id INTEGER NOT NULL DEFAULT 1,
      category TEXT NOT NULL,
      monthly_limit REAL NOT NULL DEFAULT 0,
      PRIMARY KEY (organization_id, category)
    )
  `);
  const insertOld = db.prepare('INSERT INTO budget_limits (organization_id, category, monthly_limit) VALUES (1, ?, ?)');
  oldRows.forEach(r => insertOld.run(r.category, r.monthly_limit));
  db.exec('DROP TABLE budget_limits_old');
  console.log('✓ Миграция: budget_limits привязаны к организации (старые лимиты перенесены в организацию №1)');
}

// ---------- Дефолтные лимиты бюджета для организации №1 (если совсем пусто) ----------
const limitCount = db.prepare('SELECT COUNT(*) AS c FROM budget_limits').get().c;
if (limitCount === 0) {
  const defaults = {
    'Зарплата': 300000, 'Аренда': 100000, 'Налоги': 80000, 'Закупки': 60000,
    'Софт': 30000, 'Маркетинг': 50000, 'Офис': 20000, 'Коммунальные': 15000,
    'Страховка': 10000, 'Разное': 20000
  };
  const insert = db.prepare('INSERT INTO budget_limits (organization_id, category, monthly_limit) VALUES (1, ?, ?)');
  for (const [cat, limit] of Object.entries(defaults)) insert.run(cat, limit);
  console.log('✓ Созданы лимиты бюджета по умолчанию для организации №1');
}

// ---------- Пользователи по умолчанию (из .env) ----------
function ensureUser(username, plainPassword, role) {
  if (!username || !plainPassword) return;
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(username);
  if (existing) return;
  const hash = bcrypt.hashSync(plainPassword, 10);
  db.prepare(`
    INSERT INTO users (username, password_hash, role, password_changed_at)
    VALUES (?, ?, ?, datetime('now'))
  `).run(username, hash, role);
  console.log(`✓ Создан пользователь "${username}" (роль: ${role})`);
}

ensureUser(process.env.OWNER_USERNAME, process.env.OWNER_PASSWORD, 'owner');
ensureUser(process.env.ACCOUNTANT_USERNAME, process.env.ACCOUNTANT_PASSWORD, 'accountant');

// ---------- Миграция: детальный учёт зарплаты (сотрудник, тип выплаты, период) ----------
const txCols2 = db.prepare("PRAGMA table_info(transactions)").all().map(c => c.name);
const payrollFields = { employee_id: 'INTEGER', payroll_type: 'TEXT', payroll_period: 'TEXT' };
Object.entries(payrollFields).forEach(([col, type]) => {
  if (!txCols2.includes(col)) {
    db.exec(`ALTER TABLE transactions ADD COLUMN ${col} ${type}`);
    console.log(`✓ Миграция: добавлена колонка "${col}" в transactions`);
  }
});

// ---------- Миграция: закрепление бесед (pinned_at) ----------
const convMemberCols = db.prepare("PRAGMA table_info(conversation_members)").all().map(c => c.name);
if (convMemberCols.length && !convMemberCols.includes('pinned_at')) {
  db.exec('ALTER TABLE conversation_members ADD COLUMN pinned_at TEXT');
  console.log('✓ Миграция: добавлена колонка "pinned_at" в conversation_members');
}

// ---------- Миграция: старые личные сообщения (messages) → новая модель бесед ----------
const oldMessagesTable = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'").get();
if (oldMessagesTable) {
  const oldMsgs = db.prepare('SELECT * FROM messages ORDER BY created_at ASC').all();
  const dmCache = {};
  const findOrCreateDm = (a, b) => {
    const key = [a, b].sort((x, y) => x - y).join('-');
    if (dmCache[key]) return dmCache[key];
    const info = db.prepare(`INSERT INTO conversations (type, created_at) VALUES ('dm', datetime('now'))`).run();
    db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)').run(info.lastInsertRowid, a);
    db.prepare('INSERT INTO conversation_members (conversation_id, user_id) VALUES (?, ?)').run(info.lastInsertRowid, b);
    dmCache[key] = info.lastInsertRowid;
    return info.lastInsertRowid;
  };
  oldMsgs.forEach(m => {
    const convId = findOrCreateDm(m.sender_id, m.recipient_id);
    db.prepare(`
      INSERT INTO chat_messages (conversation_id, sender_id, body, created_at) VALUES (?, ?, ?, ?)
    `).run(convId, m.sender_id, m.body, m.created_at);
  });
  db.exec('DROP TABLE messages');
  console.log(`✓ Миграция: ${oldMsgs.length} личных сообщений перенесены в новую модель бесед (группы + вложения)`);
}

console.log('База данных готова: finance.db');

module.exports = db;
