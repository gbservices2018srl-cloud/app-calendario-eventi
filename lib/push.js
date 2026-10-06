// Notifiche sul dispositivo (Web Push). Le chiavi VAPID vengono create al primo avvio e salvate nel database,
// così non serve configurare nulla su Render. Funziona sui telefoni con l'app installata nella schermata Home
// (iPhone con iOS 16.4 o successivo) e sui browser di computer e Android.
const webpush = require('web-push');
const db = require('./db');

let keys = null;
async function init() {
  if (keys) return keys;
  const { rows } = await db.q(`select key, value from app_settings where key in ('vapid_public','vapid_private')`);
  const m = Object.fromEntries(rows.map(r => [r.key, r.value]));
  if (m.vapid_public && m.vapid_private) keys = { publicKey: m.vapid_public, privateKey: m.vapid_private };
  else {
    keys = webpush.generateVAPIDKeys();
    await db.q(`insert into app_settings (key, value) values ('vapid_public',$1),('vapid_private',$2)
      on conflict (key) do nothing`, [keys.publicKey, keys.privateKey]);
    const again = await db.q(`select key, value from app_settings where key in ('vapid_public','vapid_private')`);
    const k = Object.fromEntries(again.rows.map(r => [r.key, r.value]));
    keys = { publicKey: k.vapid_public, privateKey: k.vapid_private };
  }
  webpush.setVapidDetails(process.env.VAPID_SUBJECT || 'https://calendario.appgestione.it', keys.publicKey, keys.privateKey);
  return keys;
}
async function publicKey() { return (await init()).publicKey; }

// Invia a tutti i dispositivi delle persone indicate. Restituisce l'insieme delle persone raggiunte su almeno un dispositivo.
async function sendToUsers(userIds, payload) {
  await init();
  const reached = new Set();
  if (!userIds.length) return reached;
  const { rows } = await db.q('select endpoint, user_id, p256dh, auth from push_subs where user_id = any($1)', [userIds]);
  const body = JSON.stringify(payload);
  await Promise.all(rows.map(async s => {
    try {
      await webpush.sendNotification({ endpoint: s.endpoint, keys: { p256dh: s.p256dh, auth: s.auth } }, body, { TTL: 60 * 60 * 24, urgency: 'high' });
      reached.add(s.user_id);
    } catch (e) {
      // dispositivo disinstallato o permesso revocato: l'iscrizione non vale più
      if (e.statusCode === 404 || e.statusCode === 410) await db.q('delete from push_subs where endpoint = $1', [s.endpoint]).catch(() => {});
      else console.warn('Notifica non inviata:', e.statusCode || e.message);
    }
  }));
  return reached;
}

module.exports = { init, publicKey, sendToUsers };
