/**
 * ============================================================
 * ФИНАНСОВЫЙ TELEGRAM-БОТ — Уведомления о новых записях
 * ============================================================
 *
 * ЧТО ДЕЛАЕТ ЭТОТ СКРИПТ:
 * При добавлении новой строки в Google Sheets (бухгалтером)
 * автоматически отправляет красиво оформленное уведомление
 * в Telegram с деталями записи и итогом расходов за день.
 *
 * ============================================================
 * НАСТРОЙКА (сделать один раз):
 * ============================================================
 * 1. Открой Google Sheets → Расширения → Apps Script
 * 2. Удали весь код по умолчанию, вставь этот файл целиком
 * 3. Заполни константы ниже (TELEGRAM_TOKEN, CHAT_ID)
 * 4. Сохрани (Ctrl+S / Cmd+S)
 * 5. Слева нажми на часы (Триггеры) → "+ Добавить триггер"
 *    - Функция: onEdit
 *    - Источник события: "Из электронной таблицы"
 *    - Тип события: "При изменении" (или "onFormSubmit" если через Google Forms)
 * 6. Разреши доступ, когда Google запросит подтверждение
 * 7. Протестируй: впиши тестовую строку в таблицу
 * ============================================================
 */

// ==================== НАСТРОЙКИ (ЗАПОЛНИ ЭТО) ====================

const TELEGRAM_TOKEN = '8876724289:AAFcmDvLb9N7XC5gBb7cZJYHhDiU3u1dE6U';
const CHAT_ID = '597766797';

// Названия колонок в таблице (должны совпадать с заголовками в строке 1)
const COLUMNS = {
  DATE: 'Дата',
  CATEGORY: 'Категория',
  AMOUNT: 'Сумма',
  DESCRIPTION: 'Описание',
  STATUS: 'Статус',
  RESPONSIBLE: 'Ответственный'
};

// Название листа, за которым следим (обычно "Лист1" или укажи своё)
const SHEET_NAME = 'Лист1';

// Категории и их месячные лимиты (для будущих алертов в Фазе 2-3)
const BUDGET_LIMITS = {
  'Зарплата': 300000,
  'Аренда': 100000,
  'Налоги': 80000,
  'Закупки': 60000,
  'Софт': 30000,
  'Маркетинг': 50000,
  'Офис': 20000,
  'Коммунальные': 15000,
  'Страховка': 10000,
  'Разное': 20000
};

// ==================== ОСНОВНАЯ ЛОГИКА ====================

/**
 * Срабатывает при редактировании таблицы — НО только через установленный
 * (installable) триггер, который нужно создать вручную в разделе "Триггеры".
 *
 * ВАЖНО: функция намеренно называется НЕ "onEdit", а "handleSheetEdit" —
 * это сделано специально, чтобы избежать конфликта с автоматическим
 * "простым триггером" Google (он запускается сам для любой функции с
 * именем onEdit, без прав на внешние запросы, и мешает установленному
 * триггеру, вызывая гонку и ошибку "e is undefined").
 */
function handleSheetEdit(e) {
  try {
    // Защита: если функция запущена вручную кнопкой ▶️ в редакторе
    // (а не реальным изменением в таблице), объект события e будет
    // отсутствовать — в этом случае просто тихо выходим, без ошибки.
    if (!e || !e.range) {
      console.log('handleSheetEdit запущена без события правки таблицы (вероятно, вручную через ▶️). Пропускаем.');
      return;
    }

    const sheet = e.range.getSheet();

    // Работаем только с нужным листом
    if (sheet.getName() !== SHEET_NAME) return;

    const editedRow = e.range.getRow();

    // Пропускаем заголовок (строка 1)
    if (editedRow === 1) return;

    // Получаем заголовки колонок
    const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
    const rowData = sheet.getRange(editedRow, 1, 1, sheet.getLastColumn()).getValues()[0];

    // Собираем данные строки в объект { "Дата": ..., "Категория": ..., ... }
    const record = {};
    headers.forEach((header, i) => {
      record[header] = rowData[i];
    });

    // Проверяем, что обязательные поля заполнены (иначе строка ещё не готова)
    if (!record[COLUMNS.CATEGORY] || !record[COLUMNS.AMOUNT]) return;

    // Защита от повторной отправки: помечаем строку служебным флагом в скрытой колонке
    const notifiedCol = getOrCreateNotifiedColumn(sheet, headers.length);
    const alreadyNotified = sheet.getRange(editedRow, notifiedCol).getValue();
    if (alreadyNotified === 'sent') return;

    // Считаем итог расходов за сегодня
    const todayTotal = calculateTodayTotal(sheet, headers, record[COLUMNS.DATE]);

    // Считаем итог по категории за месяц (для будущего % от лимита)
    const categoryMonthTotal = calculateCategoryMonthTotal(sheet, headers, record[COLUMNS.CATEGORY], record[COLUMNS.DATE]);
    const limit = BUDGET_LIMITS[record[COLUMNS.CATEGORY]] || null;
    const percentUsed = limit ? Math.round((categoryMonthTotal / limit) * 100) : null;

    // Формируем и отправляем сообщение
    const message = buildMessage(record, todayTotal, categoryMonthTotal, limit, percentUsed);
    sendTelegramMessage(message);

    // Отмечаем строку как отправленную
    sheet.getRange(editedRow, notifiedCol).setValue('sent');

  } catch (err) {
    // В случае ошибки — не роняем скрипт, а логируем
    console.error('Ошибка в handleSheetEdit: ' + err.message);
  }
}

/**
 * Считает сумму всех трат за ту же дату, что и в новой записи.
 */
function calculateTodayTotal(sheet, headers, targetDate) {
  const dateCol = headers.indexOf(COLUMNS.DATE);
  const amountCol = headers.indexOf(COLUMNS.AMOUNT);
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return 0;

  const data = sheet.getRange(2, 1, lastRow - 1, sheet.getLastColumn()).getValues();
  const targetDateStr = formatDate(targetDate);

  let total = 0;
  data.forEach(row => {
    if (formatDate(row[dateCol]) === targetDateStr) {
      total += Number(row[amountCol]) || 0;
    }
  });
  return total;
}

/**
 * Считает сумму трат по категории за текущий месяц.
 */
function calculateCategoryMonthTotal(sheet, headers, category, targetDate) {
  const dateCol = headers.indexOf(COLUMNS.DATE);
  const categoryCol = headers.indexOf(COLUMNS.CATEGORY);
  const amountCol = headers.indexOf(COLUMNS.AMOUNT);
  const lastRow = sheet.getLastRow();
  if (lastRow < 2) return 0;

  const data = sheet.getRange(2, 1, lastRow - 1, sheet.getLastColumn()).getValues();
  const target = new Date(targetDate);
  const targetMonth = target.getMonth();
  const targetYear = target.getFullYear();

  let total = 0;
  data.forEach(row => {
    const rowDate = new Date(row[dateCol]);
    if (row[categoryCol] === category &&
        rowDate.getMonth() === targetMonth &&
        rowDate.getFullYear() === targetYear) {
      total += Number(row[amountCol]) || 0;
    }
  });
  return total;
}

/**
 * Находит (или создаёт) служебную колонку "_notified" для защиты от дублей.
 */
function getOrCreateNotifiedColumn(sheet, headerCount) {
  const headers = sheet.getRange(1, 1, 1, sheet.getLastColumn()).getValues()[0];
  let col = headers.indexOf('_notified') + 1;
  if (col === 0) {
    col = headerCount + 1;
    sheet.getRange(1, col).setValue('_notified');
    sheet.hideColumns(col);
  }
  return col;
}

/**
 * Форматирует дату в строку YYYY-MM-DD для сравнения.
 */
function formatDate(date) {
  if (!date) return '';
  const d = new Date(date);
  return Utilities.formatDate(d, Session.getScriptTimeZone(), 'yyyy-MM-dd');
}

/**
 * Собирает текст сообщения для Telegram.
 */
function buildMessage(record, todayTotal, categoryMonthTotal, limit, percentUsed) {
  const dateStr = formatDate(record[COLUMNS.DATE]);
  const amount = Number(record[COLUMNS.AMOUNT]) || 0;

  let msg = '';
  msg += '💰 *Новая запись в финансах*\n';
  msg += '━━━━━━━━━━━━━━━━━━\n';
  msg += `📅 Дата: ${dateStr}\n`;
  msg += `🏷️ Категория: ${record[COLUMNS.CATEGORY]}\n`;
  msg += `💵 Сумма: ${formatNumber(amount)} ₽\n`;
  if (record[COLUMNS.DESCRIPTION]) {
    msg += `📝 Описание: ${record[COLUMNS.DESCRIPTION]}\n`;
  }
  if (record[COLUMNS.RESPONSIBLE]) {
    msg += `👤 Внёс: ${record[COLUMNS.RESPONSIBLE]}\n`;
  }
  msg += '━━━━━━━━━━━━━━━━━━\n';
  msg += `📈 Итого расходов сегодня: ${formatNumber(todayTotal)} ₽\n`;

  if (limit) {
    const flag = percentUsed >= 100 ? '🔴' : percentUsed >= 80 ? '🟡' : '🟢';
    msg += `${flag} Категория "${record[COLUMNS.CATEGORY]}" за месяц: ${formatNumber(categoryMonthTotal)} ₽ из ${formatNumber(limit)} ₽ (${percentUsed}%)`;
  }

  return msg;
}

function formatNumber(num) {
  return Number(num).toLocaleString('ru-RU');
}

/**
 * Отправляет сообщение в Telegram через Bot API.
 */
function sendTelegramMessage(text) {
  const url = `https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`;
  const payload = {
    chat_id: CHAT_ID,
    text: text,
    parse_mode: 'Markdown'
  };
  const options = {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    muteHttpExceptions: true
  };
  const response = UrlFetchApp.fetch(url, options);
  console.log(response.getContentText());
}

// ==================== ТЕСТОВАЯ ФУНКЦИЯ ====================

/**
 * Запусти эту функцию вручную (кнопка ▶️ в редакторе), чтобы проверить,
 * что токен и chat_id настроены верно — придёт тестовое сообщение.
 */
function testConnection() {
  sendTelegramMessage('✅ Бот подключён успешно! Финансовые уведомления настроены.');
}
