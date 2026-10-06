// Database PostgreSQL: tabelle, dati iniziali e amministratore dalle impostazioni di Render.
const { Pool, types } = require('pg');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');

// Le date restano testo "AAAA-MM-GG" (niente conversioni di fuso orario).
types.setTypeParser(1082, v => v);

// Con URL "External" di Render serve SSL; con URL "Internal" (stessa regione) no.
const url = process.env.DATABASE_URL || '';
const useSsl = process.env.PGSSL === 'true' || /\.render\.com/.test(url);
// Spazio separato nel database: il database è condiviso con le altre app del gruppo.
const SCHEMA = (process.env.DB_SCHEMA || 'calendario').replace(/[^a-z0-9_]/gi, '').toLowerCase() || 'calendario';
const pool = new Pool({
  connectionString: url,
  ssl: useSsl ? { rejectUnauthorized: false } : false,
  options: `-c search_path=${SCHEMA},public`,
});

const q = (text, params) => pool.query(text, params);
const newId = () => crypto.randomUUID();

async function migrate() {
  await q(`create schema if not exists ${SCHEMA}`);
  await q(`
    create table if not exists users (
      id text primary key,
      username text unique not null,
      name text not null default '',
      role text not null default 'staff' check (role in ('admin','staff')),
      password_hash text not null,
      active boolean not null default true,
      from_env boolean not null default false,
      last_login timestamptz,
      created_at timestamptz not null default now()
    );
    create table if not exists categories (
      id text primary key,
      name text not null,
      sort int not null default 0
    );
    create table if not exists user_categories (
      user_id text not null references users(id) on delete cascade,
      category_id text not null references categories(id) on delete cascade,
      primary key (user_id, category_id)
    );
    create table if not exists event_types (
      id text primary key,
      name text not null,
      color text not null default 'teal',
      sort int not null default 0
    );
    create table if not exists locations (
      id text primary key,
      name text not null,
      address text not null default '',
      sort int not null default 0
    );
    create table if not exists events (
      id text primary key,
      title text not null,
      type_id text references event_types(id) on delete set null,
      location_id text references locations(id) on delete set null,
      location_note text not null default '',
      start_date date not null,
      end_date date,
      all_day boolean not null default false,
      start_time time,
      end_time time,
      description text not null default '',
      link text not null default '',
      all_staff boolean not null default false,
      created_at timestamptz not null default now(),
      updated_at timestamptz not null default now(),
      updated_by text
    );
    create index if not exists events_start_idx on events(start_date);
    create table if not exists event_categories (
      event_id text not null references events(id) on delete cascade,
      category_id text not null references categories(id) on delete cascade,
      primary key (event_id, category_id)
    );
  `);
}

// Crea o aggiorna l'amministratore definito in ADMIN_USERNAME / ADMIN_PASSWORD.
async function ensureEnvAdmin() {
  const username = (process.env.ADMIN_USERNAME || '').trim().toLowerCase();
  const password = process.env.ADMIN_PASSWORD || '';
  if (!username || !password) {
    console.warn('ATTENZIONE: imposta ADMIN_USERNAME e ADMIN_PASSWORD su Render per poter entrare come amministratore.');
    return;
  }
  let { rows } = await q('select * from users where username = $1', [username]);
  if (!rows.length) {
    // Nome utente cambiato su Render: rinomina l'amministratore principale invece di crearne un secondo.
    const prev = await q('select * from users where from_env = true order by created_at limit 1');
    if (prev.rows.length) {
      await q('update users set username = $2 where id = $1', [prev.rows[0].id, username]);
      await q(`delete from session where sess->>'uid' = $1`, [prev.rows[0].id]).catch(() => {});
      rows = [{ ...prev.rows[0], username }];
    }
  }
  if (!rows.length) {
    await q(`insert into users (id, username, name, role, password_hash, from_env)
             values ($1, $2, $3, 'admin', $4, true)`,
      [newId(), username, process.env.ADMIN_NAME || username, await bcrypt.hash(password, 12)]);
    console.log(`Amministratore "${username}" creato.`);
  } else {
    const u = rows[0];
    const same = await bcrypt.compare(password, u.password_hash);
    if (!same || u.role !== 'admin' || !u.from_env || !u.active) {
      await q('update users set password_hash = $2, role = $3, from_env = true, active = true where id = $1',
        [u.id, same ? u.password_hash : await bcrypt.hash(password, 12), 'admin']);
      console.log(`Amministratore "${username}" aggiornato dalle impostazioni.`);
    }
  }
}

// Al primo avvio crea le categorie dello staff e i tipi di evento più comuni (tutto modificabile dall'app).
async function seedIfEmpty() {
  if (process.env.SKIP_SEED === 'true') return;
  const { rows } = await q('select (select count(*) from categories)::int as c, (select count(*) from event_types)::int as t');
  if (!rows[0].c) {
    const cats = ['Medici', 'RUL', 'REC', 'ASO', 'Manager', 'Operation', 'Extra-ambulatoriali'];
    for (const [i, name] of cats.entries()) await q('insert into categories (id, name, sort) values ($1,$2,$3)', [newId(), name, i]);
  }
  if (!rows[0].t) {
    const tps = [['Formazione', 'teal'], ['Riunione', 'blue'], ['Evento aziendale', 'orange'], ['Congresso', 'purple'], ['Scadenza', 'red']];
    for (const [i, [name, color]] of tps.entries()) await q('insert into event_types (id, name, color, sort) values ($1,$2,$3,$4)', [newId(), name, color, i]);
  }
}

module.exports = { pool, q, newId, SCHEMA, migrate, ensureEnvAdmin, seedIfEmpty };
