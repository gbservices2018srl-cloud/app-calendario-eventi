# Calendario eventi

Il calendario aziendale del gruppo: formazione, riunioni ed eventi. Ogni persona dello staff entra con nome utente e password e vede solo gli eventi pensati per lei.

- **Staff**: calendario del mese o in elenco, dettaglio dell'evento, "Aggiungi al mio calendario" (file .ics per telefono, Outlook e Google), cambio password.
- **Amministratore**: crea gli eventi (titolo, tipo, sede, data e ora, descrizione, link) e decide chi li vede: tutto lo staff oppure solo alcune categorie. Gestisce gli accessi delle persone, le categorie, i tipi di evento con il loro colore e le sedi. Con "Vedi come" controlla il calendario come lo vede una categoria.

Categorie create al primo avvio (modificabili da **Impostazioni**): Medici, RUL, REC, ASO, Manager, Operation, Extra-ambulatoriali.

## Messa online su Render
L'app usa il database PostgreSQL già esistente del gruppo (`mappa-protocolli-db`), con le sue tabelle nello schema separato `calendario`.

| Impostazione | Cosa mettere |
|---|---|
| `DATABASE_URL` | la "Internal Database URL" di `mappa-protocolli-db` |
| `DB_SCHEMA` | `calendario` |
| `SESSION_SECRET` | una frase lunga e casuale |
| `ADMIN_USERNAME` / `ADMIN_PASSWORD` | l'amministratore principale |
| `ADMIN_NAME` | il nome mostrato, per esempio `Giancarlo` |

Build: `npm install` · Start: `npm start` · Health check: `/healthz`.

Indirizzo: `calendario.appgestione.it` (dominio personalizzato del servizio su Render, con un record CNAME verso l'indirizzo `onrender.com`).

### Cambiare le credenziali dell'amministratore
Su Render apri il servizio, poi **Environment**: modifica `ADMIN_USERNAME` o `ADMIN_PASSWORD` e salva. Al riavvio valgono le nuove credenziali.

## Sicurezza
- Password cifrate (bcrypt); massimo 10 tentativi di accesso ogni 15 minuti.
- Il filtro "chi vede cosa" è fatto sul server: una persona non riceve mai gli eventi delle categorie non sue, nemmeno con il file .ics.
- Disattivando o eliminando un accesso la persona viene disconnessa subito.

## Provare sul computer (facoltativo)
Servono Node.js 20+ e PostgreSQL.
```bash
cp .env.example .env   # compila i valori
npm install
node --env-file=.env server.js
```
