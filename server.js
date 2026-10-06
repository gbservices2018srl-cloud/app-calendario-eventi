// Calendario eventi — server
// Avvio: npm start. Impostazioni (variabili d'ambiente su Render): vedi README.md e .env.example
const path = require('path');
const express = require('express');
const session = require('express-session');
const PgStore = require('connect-pg-simple')(session);
const bcrypt = require('bcryptjs');
const db = require('./lib/db');
const push = require('./lib/push');

const PORT = process.env.PORT || 3000;
const PROD = process.env.NODE_ENV === 'production';
const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');

app.use((req, res, next) => {
  res.set({ 'X-Frame-Options': 'DENY', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'same-origin' });
  next();
});
app.use(express.json({ limit: '200kb' }));
app.use(session({
  store: new PgStore({ pool: db.pool, schemaName: db.SCHEMA, createTableIfMissing: true }),
  name: 'cal.sid',
  secret: process.env.SESSION_SECRET || 'cambia-questa-chiave',
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: { httpOnly: true, sameSite: 'lax', secure: PROD, maxAge: 30 * 24 * 60 * 60 * 1000 },
}));

const wrap = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const bad = (res, code, msg) => res.status(code).json({ error: msg });
const str = (v, max = 200) => String(v ?? '').trim().slice(0, max);
const ids = v => (Array.isArray(v) ? v : []).map(x => String(x).slice(0, 64));

/* ---------- autenticazione ---------- */
async function loadUser(req, res, next) {
  if (!req.session.uid) return next();
  const { rows } = await db.q('select id, username, name, role, from_env from users where id = $1 and active', [req.session.uid]);
  if (rows[0]) req.user = rows[0]; else req.session.destroy(() => {});
  next();
}
app.use(wrap(loadUser));
const needUser = (req, res, next) => req.user ? next() : bad(res, 401, 'Accesso richiesto');
const needAdmin = (req, res, next) => req.user?.role === 'admin' ? next() : bad(res, 403, 'Solo amministratori');

// limite ai tentativi di accesso: 10 ogni 15 minuti per indirizzo e nome utente
const attempts = new Map();
function tooMany(key) {
  const now = Date.now(), a = (attempts.get(key) || []).filter(t => now - t < 15 * 60 * 1000);
  attempts.set(key, a); return a.length >= 10;
}

app.post('/api/login', wrap(async (req, res) => {
  const username = str(req.body.username, 80).toLowerCase(), password = String(req.body.password || '');
  const key = req.ip + '|' + username;
  if (tooMany(key)) return bad(res, 429, 'Troppi tentativi. Riprova tra 15 minuti.');
  const { rows } = await db.q('select * from users where username = $1', [username]);
  const u = rows[0];
  if (!u || !(await bcrypt.compare(password, u.password_hash))) {
    attempts.get(key).push(Date.now());
    return bad(res, 401, 'Nome utente o password non corretti.');
  }
  if (!u.active) return bad(res, 403, 'Questo accesso è stato disattivato. Rivolgiti all\'amministrazione.');
  attempts.delete(key);
  await db.q('update users set last_login = now() where id = $1', [u.id]);
  req.session.regenerate(err => {
    if (err) return bad(res, 500, 'Errore di sessione');
    req.session.uid = u.id;
    res.json({ ok: true, role: u.role });
  });
}));
app.post('/api/logout', (req, res) => req.session.destroy(() => { res.clearCookie('cal.sid'); res.json({ ok: true }); }));
app.post('/api/me/password', needUser, wrap(async (req, res) => {
  const { current, next: nw } = req.body;
  if (!nw || String(nw).length < 8) return bad(res, 400, 'La nuova password deve avere almeno 8 caratteri.');
  if (req.user.from_env) return bad(res, 400, 'La password dell\'amministratore principale si cambia dalle impostazioni di Render (ADMIN_PASSWORD).');
  const { rows } = await db.q('select password_hash from users where id = $1', [req.user.id]);
  if (!(await bcrypt.compare(String(current || ''), rows[0].password_hash))) return bad(res, 400, 'La password attuale non è corretta.');
  await db.q('update users set password_hash = $2 where id = $1', [req.user.id, await bcrypt.hash(String(nw), 12)]);
  res.json({ ok: true });
}));

/* ---------- dati di base ---------- */
async function lists() {
  const [c, t, l] = await Promise.all([
    db.q('select id, name from categories order by sort, name'),
    db.q('select id, name, color from event_types order by sort, name'),
    db.q('select id, name, address from locations order by sort, name'),
  ]);
  return { categories: c.rows, types: t.rows, locations: l.rows };
}
async function myCategories(userId) {
  const { rows } = await db.q('select category_id from user_categories where user_id = $1', [userId]);
  return rows.map(r => r.category_id);
}

app.get('/api/state', needUser, wrap(async (req, res) => {
  const out = { me: { id: req.user.id, username: req.user.username, name: req.user.name, role: req.user.role, fromEnv: req.user.from_env },
    ...(await lists()) };
  out.me.categories = await myCategories(req.user.id);
  if (req.user.role === 'admin') {
    const { rows: users } = await db.q(`select u.id, u.username, u.name, u.role, u.active, u.from_env,
      to_char(u.last_login at time zone 'Europe/Rome', 'YYYY-MM-DD HH24:MI') as last_login,
      coalesce(array_agg(uc.category_id) filter (where uc.category_id is not null), '{}') as categories
      from users u left join user_categories uc on uc.user_id = u.id group by u.id order by u.role, u.name`);
    out.users = users.map(u => ({ id: u.id, username: u.username, name: u.name, role: u.role, active: u.active,
      fromEnv: u.from_env, lastLogin: u.last_login, categories: u.categories }));
  }
  res.json(out);
}));

/* ---------- eventi ---------- */
const isDate = s => /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s + 'T00:00:00Z'));
const isTime = s => /^([01]\d|2[0-3]):[0-5]\d$/.test(s);
const EVENT_COLS = `e.id, e.title, e.type_id, e.location_id, e.location_note, e.start_date, e.end_date, e.all_day,
  to_char(e.start_time, 'HH24:MI') as start_time, to_char(e.end_time, 'HH24:MI') as end_time,
  e.description, e.link, e.all_staff, e.rsvp,
  coalesce((select array_agg(category_id) from event_categories ec where ec.event_id = e.id), '{}') as categories`;
const shape = e => ({ id: e.id, title: e.title, typeId: e.type_id, locationId: e.location_id, locationNote: e.location_note,
  start: e.start_date, end: e.end_date || e.start_date, allDay: e.all_day, startTime: e.start_time, endTime: e.end_time,
  description: e.description, link: e.link, allStaff: e.all_staff, categories: e.categories, rsvp: e.rsvp,
  ...(e.my_rsvp !== undefined ? { myRsvp: e.my_rsvp } : {}), ...(e.att ? { att: e.att } : {}) });

// Chi è chiamato a rispondere a un evento: lo staff attivo che può vederlo (gli amministratori no).
const AUDIENCE = (ev, usr) => `${usr}.active and ${usr}.role = 'staff' and (${ev}.all_staff or exists (select 1 from event_categories ec
  join user_categories uc on uc.category_id = ec.category_id where ec.event_id = ${ev}.id and uc.user_id = ${usr}.id))`;

// Il controllo di chi vede cosa avviene qui sul server: un collaboratore non riceve mai gli eventi non suoi.
function visibilityClause(user, params) {
  if (user.role === 'admin') return 'true';
  params.push(user.id);
  return `(e.all_staff or exists (select 1 from event_categories ec join user_categories uc on uc.category_id = ec.category_id
    where ec.event_id = e.id and uc.user_id = $${params.length}))`;
}

app.get('/api/events', needUser, wrap(async (req, res) => {
  const from = str(req.query.from, 10), to = str(req.query.to, 10);
  if (!isDate(from) || !isDate(to)) return bad(res, 400, 'Periodo non valido.');
  const params = [from, to];
  const vis = visibilityClause(req.user, params);
  let extra = '';
  if (req.user.role === 'admin') extra = `, case when e.rsvp then (select json_build_object('total', count(*), 'yes', count(*) filter (where r.status = 'yes'),
      'no', count(*) filter (where r.status = 'no')) from users u left join rsvp r on r.event_id = e.id and r.user_id = u.id
      where ${AUDIENCE('e', 'u')}) end as att`;
  else { params.push(req.user.id); extra = `, (select status from rsvp where event_id = e.id and user_id = $${params.length}) as my_rsvp`; }
  const { rows } = await db.q(`select ${EVENT_COLS}${extra} from events e
    where e.start_date <= $2 and coalesce(e.end_date, e.start_date) >= $1 and ${vis}
    order by e.start_date, e.all_day desc, e.start_time nulls first, e.title limit 2000`, params);
  // numero di settimana scelto dall'amministrazione (1, 2, 3, 4, 4bis), indicato dal lunedì
  const { rows: wk } = await db.q(`select week_start, label from week_labels where week_start between ($1::date - 6) and $2`, [from, to]);
  res.json({ events: rows.map(shape), weeks: Object.fromEntries(wk.map(w => [w.week_start, w.label])) });
}));

function eventFields(b) {
  const f = {
    title: str(b.title, 160), typeId: str(b.typeId, 64) || null, locationId: str(b.locationId, 64) || null,
    locationNote: str(b.locationNote, 200), start: str(b.start, 10), end: str(b.end, 10), allDay: !!b.allDay,
    startTime: str(b.startTime, 5), endTime: str(b.endTime, 5), description: str(b.description, 5000),
    link: str(b.link, 500), allStaff: !!b.allStaff, categories: ids(b.categories), rsvp: b.rsvp !== false,
  };
  if (!f.title) return 'Manca il titolo.';
  if (!isDate(f.start)) return 'Manca la data.';
  if (!f.end || !isDate(f.end) || f.end < f.start) f.end = f.start;
  if (f.allDay) { f.startTime = null; f.endTime = null; }
  else {
    if (!isTime(f.startTime)) return 'Manca l\'ora di inizio (oppure segna "Tutto il giorno").';
    if (f.endTime && !isTime(f.endTime)) return 'Ora di fine non valida.';
    if (!f.endTime) f.endTime = null;
    if (f.endTime && f.end === f.start && f.endTime <= f.startTime) return 'L\'ora di fine è prima dell\'inizio.';
  }
  if (f.link && !/^https?:\/\//i.test(f.link)) f.link = 'https://' + f.link;
  if (!f.allStaff && !f.categories.length) return 'Scegli chi può vedere l\'evento: tutto lo staff o almeno una categoria.';
  if (f.allStaff) f.categories = [];
  return f;
}
async function saveCategories(eventId, cats) {
  await db.q('delete from event_categories where event_id = $1', [eventId]);
  if (cats.length) await db.q(`insert into event_categories (event_id, category_id)
    select $1, id from categories where id = any($2) on conflict do nothing`, [eventId, cats]);
}
app.post('/api/events', needAdmin, wrap(async (req, res) => {
  const f = eventFields(req.body);
  if (typeof f === 'string') return bad(res, 400, f);
  const id = db.newId();
  await db.q(`insert into events (id, title, type_id, location_id, location_note, start_date, end_date, all_day, start_time, end_time,
    description, link, all_staff, updated_by, rsvp) values ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
    [id, f.title, f.typeId, f.locationId, f.locationNote, f.start, f.end, f.allDay, f.startTime, f.endTime, f.description, f.link, f.allStaff, req.user.name, f.rsvp]);
  await saveCategories(id, f.categories);
  res.json({ id });
}));
app.put('/api/events/:id', needAdmin, wrap(async (req, res) => {
  const f = eventFields(req.body);
  if (typeof f === 'string') return bad(res, 400, f);
  const r = await db.q(`update events set title=$2, type_id=$3, location_id=$4, location_note=$5, start_date=$6, end_date=$7, all_day=$8,
    start_time=$9, end_time=$10, description=$11, link=$12, all_staff=$13, updated_by=$14, rsvp=$15, updated_at=now() where id=$1`,
    [req.params.id, f.title, f.typeId, f.locationId, f.locationNote, f.start, f.end, f.allDay, f.startTime, f.endTime, f.description, f.link, f.allStaff, req.user.name, f.rsvp]);
  if (!r.rowCount) return bad(res, 404, 'Evento non trovato.');
  await saveCategories(req.params.id, f.categories);
  res.json({ ok: true });
}));
app.delete('/api/events/:id', needAdmin, wrap(async (req, res) => {
  await db.q('delete from events where id = $1', [req.params.id]);
  res.json({ ok: true });
}));

// File .ics per aggiungere l'evento al proprio calendario (telefono, Outlook, Google).
app.get('/api/events/:id/ics', needUser, wrap(async (req, res) => {
  const params = [req.params.id];
  const vis = visibilityClause(req.user, params);
  const { rows } = await db.q(`select ${EVENT_COLS}, t.name as type_name, l.name as loc_name, l.address as loc_address
    from events e left join event_types t on t.id = e.type_id left join locations l on l.id = e.location_id
    where e.id = $1 and ${vis}`, params);
  const e = rows[0];
  if (!e) return bad(res, 404, 'Evento non trovato.');
  const esc = s => String(s || '').replace(/\\/g, '\\\\').replace(/\n/g, '\\n').replace(/([,;])/g, '\\$1');
  const d = s => s.replace(/-/g, '');
  const next = s => { const x = new Date(s + 'T12:00:00Z'); x.setUTCDate(x.getUTCDate() + 1); return x.toISOString().slice(0, 10); };
  const end = e.end_date || e.start_date;
  let when;
  if (e.all_day) when = [`DTSTART;VALUE=DATE:${d(e.start_date)}`, `DTEND;VALUE=DATE:${d(next(end))}`];
  else {
    const t = s => s.replace(':', '') + '00';
    const et = e.end_time || (() => { const [h, m] = e.start_time.split(':').map(Number); const x = Math.min(h * 60 + m + 60, 23 * 60 + 59); return `${String(Math.floor(x / 60)).padStart(2, '0')}:${String(x % 60).padStart(2, '0')}`; })();
    when = [`DTSTART;TZID=Europe/Rome:${d(e.start_date)}T${t(e.start_time)}`, `DTEND;TZID=Europe/Rome:${d(end)}T${t(et)}`];
  }
  const loc = [e.loc_name, e.loc_address, e.location_note].filter(Boolean).join(' · ');
  const desc = [e.type_name, e.description, e.link].filter(Boolean).join('\n\n');
  const now = new Date().toISOString().replace(/[-:]/g, '').replace(/\.\d+/, '');
  const ics = ['BEGIN:VCALENDAR', 'VERSION:2.0', 'PRODID:-//To Smile//Calendario eventi//IT', 'CALSCALE:GREGORIAN', 'BEGIN:VEVENT',
    `UID:${e.id}@calendario.appgestione.it`, `DTSTAMP:${now}`, ...when, `SUMMARY:${esc(e.title)}`,
    loc && `LOCATION:${esc(loc)}`, desc && `DESCRIPTION:${esc(desc)}`, e.link && `URL:${e.link}`, 'END:VEVENT', 'END:VCALENDAR']
    .filter(Boolean).join('\r\n');
  const fname = e.title.normalize('NFD').replace(/[^\w\s-]/g, '').trim().replace(/\s+/g, '-').slice(0, 60) || 'evento';
  res.set({ 'Content-Type': 'text/calendar; charset=utf-8', 'Content-Disposition': `attachment; filename="${fname}.ics"` });
  res.send(ics);
}));

/* ---------- presenze ---------- */
const todayRome = () => new Intl.DateTimeFormat('en-CA', { timeZone: 'Europe/Rome' }).format(new Date());
app.post('/api/events/:id/rsvp', needUser, wrap(async (req, res) => {
  const status = req.body.status;
  if (!['yes', 'no', null].includes(status ?? null)) return bad(res, 400, 'Risposta non valida.');
  const params = [req.params.id];
  const vis = visibilityClause(req.user, params);
  const { rows } = await db.q(`select e.rsvp, coalesce(e.end_date, e.start_date) as last_day from events e where e.id = $1 and ${vis}`, params);
  const e = rows[0];
  if (!e) return bad(res, 404, 'Evento non trovato.');
  if (!e.rsvp) return bad(res, 400, 'Per questo evento non serve la conferma.');
  if (e.last_day < todayRome()) return bad(res, 400, 'L\'evento è già passato.');
  if (status) await db.q(`insert into rsvp (event_id, user_id, status) values ($1,$2,$3)
    on conflict (event_id, user_id) do update set status = excluded.status, updated_at = now()`, [req.params.id, req.user.id, status]);
  else await db.q('delete from rsvp where event_id = $1 and user_id = $2', [req.params.id, req.user.id]);
  res.json({ ok: true });
}));
// Elenco nominativo: chi ha confermato, chi no, chi non ha ancora risposto.
app.get('/api/events/:id/attendance', needAdmin, wrap(async (req, res) => {
  const { rows } = await db.q(`select u.id, u.name, u.username, r.status,
      to_char(r.updated_at at time zone 'Europe/Rome', 'YYYY-MM-DD HH24:MI') as answered_at,
      coalesce((select array_agg(category_id) from user_categories where user_id = u.id), '{}') as categories,
      exists (select 1 from push_subs s where s.user_id = u.id) as has_push
    from events e join users u on ${AUDIENCE('e', 'u')} left join rsvp r on r.event_id = e.id and r.user_id = u.id
    where e.id = $1 order by u.name`, [req.params.id]);
  const { rows: rem } = await db.q(`select to_char(sent_at at time zone 'Europe/Rome', 'YYYY-MM-DD HH24:MI') as sent_at, recipients, sent_by
    from reminders where event_id = $1 order by sent_at desc limit 5`, [req.params.id]);
  res.json({ people: rows.map(r => ({ id: r.id, name: r.name, username: r.username, status: r.status || null, answeredAt: r.answered_at,
    categories: r.categories, hasPush: r.has_push })), reminders: rem.map(r => ({ sentAt: r.sent_at, recipients: r.recipients, by: r.sent_by })) });
}));
// Promemoria: notifica sul telefono/computer di chi non ha ancora risposto (o delle persone scelte).
app.post('/api/events/:id/remind', needAdmin, wrap(async (req, res) => {
  const { rows: evs } = await db.q(`select ${EVENT_COLS} from events e where e.id = $1`, [req.params.id]);
  const ev = evs[0];
  if (!ev) return bad(res, 404, 'Evento non trovato.');
  const only = ids(req.body.userIds);
  const { rows: people } = await db.q(`select u.id, u.name from events e join users u on ${AUDIENCE('e', 'u')}
    left join rsvp r on r.event_id = e.id and r.user_id = u.id
    where e.id = $1 and ${only.length ? 'u.id = any($2)' : 'r.status is null'}`, only.length ? [ev.id, only] : [ev.id]);
  if (!people.length) return res.json({ sent: 0, reached: [], unreachable: [] });
  const dt = new Date(ev.start_date + 'T12:00:00Z');
  const when = new Intl.DateTimeFormat('it-IT', { weekday: 'long', day: 'numeric', month: 'long', timeZone: 'UTC' }).format(dt)
    + (ev.all_day ? '' : ` alle ${ev.start_time}`);
  const result = await push.sendToUsers(people.map(p => p.id), {
    title: `Promemoria: ${ev.title}`,
    body: `${when.charAt(0).toUpperCase() + when.slice(1)}. ${ev.rsvp ? 'Conferma se ci sarai.' : ''}`.trim(),
    url: `/?event=${ev.id}`, tag: 'evento-' + ev.id,
  });
  const reached = people.filter(p => result.has(p.id)), unreachable = people.filter(p => !result.has(p.id));
  await db.q('insert into reminders (id, event_id, recipients, sent_by) values ($1,$2,$3,$4)', [db.newId(), ev.id, reached.length, req.user.name]);
  res.json({ sent: reached.length, reached: reached.map(p => p.name), unreachable: unreachable.map(p => p.name) });
}));

/* ---------- notifiche sul dispositivo ---------- */
app.get('/api/push/key', needUser, wrap(async (req, res) => res.json({ key: await push.publicKey() })));
app.post('/api/push/subscribe', needUser, wrap(async (req, res) => {
  const s = req.body.subscription || {};
  const endpoint = str(s.endpoint, 1000), p256dh = str(s.keys?.p256dh, 200), auth = str(s.keys?.auth, 100);
  if (!/^https:\/\//.test(endpoint) || !p256dh || !auth) return bad(res, 400, 'Iscrizione non valida.');
  await db.q(`insert into push_subs (endpoint, user_id, p256dh, auth, device) values ($1,$2,$3,$4,$5)
    on conflict (endpoint) do update set user_id = excluded.user_id, p256dh = excluded.p256dh, auth = excluded.auth, device = excluded.device`,
    [endpoint, req.user.id, p256dh, auth, str(req.get('user-agent'), 300)]);
  res.json({ ok: true });
}));
app.post('/api/push/unsubscribe', needUser, wrap(async (req, res) => {
  await db.q('delete from push_subs where endpoint = $1 and user_id = $2', [str(req.body.endpoint, 1000), req.user.id]);
  res.json({ ok: true });
}));
app.post('/api/push/test', needUser, wrap(async (req, res) => {
  const ok = await push.sendToUsers([req.user.id], { title: 'Notifiche attive', body: 'Da ora ricevi qui i promemoria degli eventi To Smile.', url: '/' });
  res.json({ ok: ok.has(req.user.id) });
}));

/* ---------- numero della settimana (admin) ---------- */
const WEEK_LABELS = ['1', '2', '3', '4', '4bis'];
app.put('/api/weeks', needAdmin, wrap(async (req, res) => {
  const list = (Array.isArray(req.body.weeks) ? req.body.weeks : []).slice(0, 120);
  for (const w of list) {
    const start = str(w.start, 10), label = str(w.label, 10);
    if (!isDate(start) || new Date(start + 'T12:00:00Z').getUTCDay() !== 1) return bad(res, 400, 'Settimana non valida.');
    if (label && !WEEK_LABELS.includes(label)) return bad(res, 400, 'Valore non valido.');
  }
  for (const w of list) {
    const start = str(w.start, 10), label = str(w.label, 10);
    if (label) await db.q(`insert into week_labels (week_start, label) values ($1,$2) on conflict (week_start) do update set label = excluded.label`, [start, label]);
    else await db.q('delete from week_labels where week_start = $1', [start]);
  }
  res.json({ ok: true });
}));

/* ---------- persone (admin) ---------- */
async function setUserCategories(userId, cats) {
  await db.q('delete from user_categories where user_id = $1', [userId]);
  if (cats.length) await db.q(`insert into user_categories (user_id, category_id)
    select $1, id from categories where id = any($2) on conflict do nothing`, [userId, cats]);
}
app.post('/api/users', needAdmin, wrap(async (req, res) => {
  const username = str(req.body.username, 60).toLowerCase(), name = str(req.body.name, 120), password = String(req.body.password || '');
  const role = req.body.role === 'admin' ? 'admin' : 'staff';
  if (!/^[a-z0-9._-]{3,}$/.test(username)) return bad(res, 400, 'Nome utente: almeno 3 caratteri tra lettere minuscole, numeri, punto, trattino.');
  if (!name) return bad(res, 400, 'Manca il nome.');
  if (password.length < 8) return bad(res, 400, 'La password deve avere almeno 8 caratteri.');
  const dup = await db.q('select 1 from users where username = $1', [username]);
  if (dup.rows.length) return bad(res, 400, 'Questo nome utente esiste già.');
  const id = db.newId();
  await db.q('insert into users (id, username, name, role, password_hash) values ($1,$2,$3,$4,$5)',
    [id, username, name, role, await bcrypt.hash(password, 12)]);
  await setUserCategories(id, ids(req.body.categories));
  res.json({ id });
}));
app.put('/api/users/:id', needAdmin, wrap(async (req, res) => {
  const { rows } = await db.q('select * from users where id = $1', [req.params.id]);
  const u = rows[0];
  if (!u) return bad(res, 404, 'Persona non trovata.');
  const name = str(req.body.name, 120) || u.name;
  let username = u.username, role = u.role, active = u.active;
  if (!u.from_env) {
    if (req.body.username !== undefined) {
      username = str(req.body.username, 60).toLowerCase();
      if (!/^[a-z0-9._-]{3,}$/.test(username)) return bad(res, 400, 'Nome utente: almeno 3 caratteri tra lettere minuscole, numeri, punto, trattino.');
      const dup = await db.q('select 1 from users where username = $1 and id <> $2', [username, u.id]);
      if (dup.rows.length) return bad(res, 400, 'Questo nome utente esiste già.');
    }
    if (req.body.role !== undefined) role = req.body.role === 'admin' ? 'admin' : 'staff';
    if (req.body.active !== undefined) active = !!req.body.active;
    if (u.id === req.user.id && (role !== 'admin' || !active)) return bad(res, 400, 'Non puoi togliere a te stesso l\'accesso da amministratore.');
  }
  await db.q('update users set name=$2, username=$3, role=$4, active=$5 where id=$1', [u.id, name, username, role, active]);
  if (req.body.password) {
    if (u.from_env) return bad(res, 400, 'La password dell\'amministratore principale si cambia da Render.');
    if (String(req.body.password).length < 8) return bad(res, 400, 'La password deve avere almeno 8 caratteri.');
    await db.q('update users set password_hash = $2 where id = $1', [u.id, await bcrypt.hash(String(req.body.password), 12)]);
    await db.q(`delete from session where sess->>'uid' = $1`, [u.id]).catch(() => {});
  }
  if (!active) await db.q(`delete from session where sess->>'uid' = $1`, [u.id]).catch(() => {});
  if (req.body.categories !== undefined) await setUserCategories(u.id, ids(req.body.categories));
  res.json({ ok: true });
}));
app.delete('/api/users/:id', needAdmin, wrap(async (req, res) => {
  const { rows } = await db.q('select from_env from users where id = $1', [req.params.id]);
  if (!rows[0]) return res.json({ ok: true });
  if (rows[0].from_env) return bad(res, 400, 'L\'amministratore principale non si può eliminare.');
  if (req.params.id === req.user.id) return bad(res, 400, 'Non puoi eliminare te stesso.');
  await db.q(`delete from session where sess->>'uid' = $1`, [req.params.id]).catch(() => {});
  await db.q('delete from users where id = $1', [req.params.id]);
  res.json({ ok: true });
}));

/* ---------- categorie, tipi, sedi (admin) ---------- */
const COLORS = ['teal', 'blue', 'orange', 'purple', 'red', 'green', 'pink', 'slate'];
const listApi = (table, fields) => {
  const pick = b => {
    const o = { name: str(b.name, 80) };
    if (fields.includes('color')) o.color = COLORS.includes(b.color) ? b.color : 'teal';
    if (fields.includes('address')) o.address = str(b.address, 200);
    return o;
  };
  app.post(`/api/${table}`, needAdmin, wrap(async (req, res) => {
    const o = pick(req.body);
    if (!o.name) return bad(res, 400, 'Manca il nome.');
    const id = db.newId();
    const { rows } = await db.q(`select coalesce(max(sort), -1) + 1 as s from ${table}`);
    const cols = ['id', 'sort', ...Object.keys(o)], vals = [id, rows[0].s, ...Object.values(o)];
    await db.q(`insert into ${table} (${cols.join(',')}) values (${cols.map((_, i) => '$' + (i + 1)).join(',')})`, vals);
    res.json({ id });
  }));
  app.put(`/api/${table}/:id`, needAdmin, wrap(async (req, res) => {
    const o = pick(req.body);
    if (!o.name) return bad(res, 400, 'Manca il nome.');
    const keys = Object.keys(o);
    await db.q(`update ${table} set ${keys.map((k, i) => `${k} = $${i + 2}`).join(', ')} where id = $1`, [req.params.id, ...Object.values(o)]);
    res.json({ ok: true });
  }));
  app.delete(`/api/${table}/:id`, needAdmin, wrap(async (req, res) => {
    await db.q(`delete from ${table} where id = $1`, [req.params.id]);
    res.json({ ok: true });
  }));
  app.post(`/api/${table}/order`, needAdmin, wrap(async (req, res) => {
    for (const [i, id] of ids(req.body.ids).entries()) await db.q(`update ${table} set sort = $2 where id = $1`, [id, i]);
    res.json({ ok: true });
  }));
};
listApi('categories', []);
listApi('event_types', ['color']);
listApi('locations', ['address']);

// Quanti eventi e persone usano una voce, per avvisare prima di eliminarla.
app.get('/api/usage', needAdmin, wrap(async (req, res) => {
  const [c1, c2, t, l] = await Promise.all([
    db.q('select category_id as id, count(*)::int as n from event_categories group by 1'),
    db.q('select category_id as id, count(*)::int as n from user_categories group by 1'),
    db.q('select type_id as id, count(*)::int as n from events where type_id is not null group by 1'),
    db.q('select location_id as id, count(*)::int as n from events where location_id is not null group by 1'),
  ]);
  const m = r => Object.fromEntries(r.rows.map(x => [x.id, x.n]));
  res.json({ catEvents: m(c1), catUsers: m(c2), types: m(t), locations: m(l) });
}));

/* ---------- pagine ---------- */
const page = file => (req, res) => {
  res.set('Cache-Control', 'no-store');
  if (file !== 'login.html' && !req.user) return res.redirect('/login');
  if (file === 'login.html' && req.user) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', file));
};
app.get('/login', page('login.html'));
app.get('/admin', (req, res) => res.redirect('/'));
app.get('/', page('app.html'));
app.get('/healthz', (req, res) => res.send('ok'));
app.get('/manifest.webmanifest', (req, res) => res.sendFile(path.join(__dirname, 'public', 'manifest.webmanifest')));
app.get('/logo.png', (req, res) => res.sendFile(path.join(__dirname, 'public', 'logo.png'), { maxAge: '7d' }));
app.get('/sw.js', (req, res) => { res.set({ 'Cache-Control': 'no-cache', 'Service-Worker-Allowed': '/' }); res.sendFile(path.join(__dirname, 'public', 'sw.js')); });
for (const f of ['icon-192.png', 'icon-512.png', 'apple-touch-icon.png']) app.get('/' + f, (req, res) => res.sendFile(path.join(__dirname, 'public', f), { maxAge: '7d' }));
app.get('/icon.svg', (req, res) => res.sendFile(path.join(__dirname, 'public', 'icon.svg')));

app.use((err, req, res, next) => {
  console.error(err);
  bad(res, 500, 'Errore del server. Riprova.');
});

(async () => {
  await db.migrate();
  await db.ensureEnvAdmin();
  await db.seedIfEmpty();
  await push.init().catch(e => console.warn('Notifiche non attive:', e.message));
  app.listen(PORT, () => console.log(`Calendario eventi attivo sulla porta ${PORT}`));
})().catch(e => { console.error('Avvio non riuscito:', e); process.exit(1); });
