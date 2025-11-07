// server.js — Vapi Middleware (Outlook only, robust)
// Node 18+, node-fetch v2

require('dotenv').config();

process.on('unhandledRejection', (e) => console.error('UNHANDLED REJECTION', e));
process.on('uncaughtException',  (e) => console.error('UNCAUGHT EXCEPTION', e));

console.log('Booting server.js ...');

const path = require('path');
const fs = require('fs');
const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch'); // v2.x
const { Issuer } = require('openid-client');
const crypto = require('crypto');

const app = express();
app.set('trust proxy', 1);
app.use(bodyParser.json());

// -----------------------------------------
// Settings & files
// -----------------------------------------
const TOKEN_FILE = process.env.TOKENS_PATH
  ? process.env.TOKENS_PATH
  : path.join(__dirname, 'token.json'); // Persistenter Tokenstore

const SCOPES = ['offline_access', 'openid', 'profile', 'email', 'Calendars.ReadWrite'];

let azureClient;

// -----------------------------------------
// Helper: strict secret header (robust + hashed logging)
// -----------------------------------------
function hash8(v) {
  return require('crypto').createHash('sha256').update(String(v || '')).digest('hex').slice(0, 8);
}
function clean(v) { return String(v || '').trim(); }

function extractIncomingSecret(req) {
  // 1) Bevorzugt: x-vapi-secret
  const headerRaw = req.get('x-vapi-secret') || req.get('X-Vapi-Secret') || '';

  // 2) Fallback: Authorization: Bearer <token>
  const auth = req.get('authorization') || req.get('Authorization') || '';
  let bearer = '';
  if (auth && /^bearer\s+/i.test(auth)) {
    bearer = auth.replace(/^bearer\s+/i, '').trim();
  }

  // 3) Weitere Fallbacks: x-api-key / query / body
  const xApiKey = req.get('x-api-key') || req.get('X-Api-Key') || '';
  const q = (req.query && req.query.secret) ? String(req.query.secret) : '';
  const b = (req.body  && req.body.secret)  ? String(req.body.secret)  : '';

  // Reihenfolge: header > bearer > x-api-key > query > body
  let candidate = clean(headerRaw || bearer || xApiKey || q || b || '');

  // Harte Sanitizer: führende Interpunktionszeichen/Spaces/NBSP entfernen
  candidate = candidate
    .replace(/^[\s,;]+/, '')   // führende Kommas/Spaces/Semikola
    .replace(/\u00A0/g, '');   // non-breaking space entfernen

  return {
    candidate,
    sources: { header: !!headerRaw, bearer: !!bearer, xApiKey: !!xApiKey, query: !!q, body: !!b },
    raw: { headerRaw, bearer, xApiKey, q, b }
  };
}

function requireVapiSecret(req, res, next) {
  const expected = clean(process.env.VAPI_SECRET || '');
  if (!expected) return next(); // Secret-Schutz aus, falls nicht gesetzt

  const { candidate, sources, raw } = extractIncomingSecret(req);

  // lauter Debug – zeigt Klartext & hex (um unsichtbare Zeichen zu sehen)
  console.log('[AUTH] expected(raw)=', expected,
              '| hdr(raw)=', raw.headerRaw || '',
              '| bearer(raw)=', raw.bearer || '',
              '| xApi(raw)=', raw.xApiKey || '',
              '| query(raw)=', raw.q || '',
              '| body(raw)=', raw.b || '');
  console.log('[AUTH] expected(hex)=', hexDump(expected),
              '| hdr(hex)=', hexDump(raw.headerRaw || ''));

  const ok = expected && candidate && (candidate === expected);
  console.log('[AUTH] eq=', ok,
              'hdr=', hash8(candidate),
              'env=', hash8(expected),
              'src=', JSON.stringify(sources));

  if (!ok) {
    return res.status(401).json({ ok:false, error:'unauthorized' });
  }
  next();
}

// Beim Booten: Hash vom ENV-Secret loggen (kein Klartext!)
console.log('[BOOT] VAPI_SECRET hash =', process.env.VAPI_SECRET ? hash8(process.env.VAPI_SECRET) : '(none)');

// -----------------------------------------
// Mini CORS/Preflight nur für Test-Tools
// -----------------------------------------
app.options('/vapi-webhook', (req, res) => {
  res.set({
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, x-vapi-intent, x-vapi-secret, Authorization, x-api-key',
    'Access-Control-Allow-Methods': 'POST, OPTIONS'
  });
  return res.status(204).end();
});

// -----------------------------------------
// Bootstrap: Falls kein token.json -> über ENV refreshen (nach Azure-Init)
// -----------------------------------------
async function bootstrapTokenFromEnvIfNeeded() {
  try {
    const hasTokenFile = fs.existsSync(TOKEN_FILE);
    if (hasTokenFile) {
      console.log('[BOOT] token.json vorhanden.');
      return;
    }

    const envRefresh = process.env.AZ_REFRESH_DEFAULT;
    if (!envRefresh) {
      console.log('[BOOT] Kein token.json und keine AZ_REFRESH_DEFAULT ENV gesetzt.');
      return;
    }
    if (!azureClient) {
      console.log('[BOOT] azureClient noch nicht initialisiert – Bootstrap wird übersprungen.');
      return;
    }

    console.log('[BOOT] Kein token.json, refreshe über ENV…');
    const refreshed = await azureClient.refresh(envRefresh);
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(refreshed, null, 2));
    console.log('[BOOT] token.json aus ENV-Refresh erstellt.');
  } catch (e) {
    console.error('[BOOT] Fehler beim Laden/Refresh aus ENV:', e);
  }
}

// -----------------------------------------
// Init Azure OpenID Client (ruft Bootstrap NACH Init)
// -----------------------------------------
(async function initAzure() {
  try {
    if (!process.env.AZ_TENANT_ID || !process.env.AZ_CLIENT_ID || !process.env.AZ_CLIENT_SECRET || !process.env.AZ_REDIRECT_URI) {
      console.warn('Azure ENV Variablen fehlen. Setze AZ_TENANT_ID, AZ_CLIENT_ID, AZ_CLIENT_SECRET, AZ_REDIRECT_URI');
      return;
    }

    const issuer = await Issuer.discover(`https://login.microsoftonline.com/${process.env.AZ_TENANT_ID}/v2.0`);
    azureClient = new issuer.Client({
      client_id: process.env.AZ_CLIENT_ID,
      client_secret: process.env.AZ_CLIENT_SECRET,
      redirect_uris: [process.env.AZ_REDIRECT_URI],
      response_types: ['code'],
    });
    console.log('Azure OIDC client initialisiert.');

    await bootstrapTokenFromEnvIfNeeded();
  } catch (e) {
    console.error('Azure init error', e);
  }
})();

// -----------------------------------------
// OAuth Flows
// -----------------------------------------
app.get('/auth/azure', async (_req, res) => {
  try {
    if (!azureClient) return res.status(500).send('Azure nicht konfiguriert.');
    const state = 'default';
    const url = azureClient.authorizationUrl({
      scope: SCOPES.join(' '),
      response_mode: 'query',
      state
    });
    console.log('[OAUTH] auth start -> state:', state);
    res.redirect(url);
  } catch (e) {
    console.error('Auth start error', e);
    res.status(500).send('Auth start error');
  }
});

app.get('/auth/azure/callback', async (req, res) => {
  try {
    if (!azureClient) return res.status(500).send('Azure nicht konfiguriert.');
    const params = azureClient.callbackParams(req);
    const state = params.state || 'default';
    console.log('[OAUTH] callback state:', state);

    const tokenSet = await azureClient.callback(
      process.env.AZ_REDIRECT_URI,
      params,
      { state }
    );

    console.log('[OAUTH] tokenSet:', {
      hasAccess: !!tokenSet.access_token,
      hasRefresh: !!tokenSet.refresh_token,
      scope: tokenSet.scope
    });

    try {
      fs.writeFileSync(TOKEN_FILE, JSON.stringify(tokenSet, null, 2));
      console.log('[OAUTH] tokenSet gespeichert -> token.json');
      console.log('[OAUTH] REFRESH_TOKEN_FOR_ENV=', tokenSet.refresh_token || '(none)');
    } catch (e) {
      console.error('Konnte token.json nicht schreiben:', e);
    }

    res.send('Microsoft Outlook verbunden. Du kannst dieses Fenster schliessen.');
  } catch (e) {
    console.error('Azure callback error', e);
    res.status(500).send('Azure callback error');
  }
});

// -----------------------------------------
// Token sicherstellen (liest token.json, refresht bei Bedarf, Bootstrap via ENV)
// -----------------------------------------
async function ensureAzureAccessToken() {
  if (!azureClient) throw new Error('Azure Client nicht initialisiert');

  let t = null;

  if (fs.existsSync(TOKEN_FILE)) {
    try {
      t = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
    } catch (e) {
      console.error('token.json lesen fehlgeschlagen:', e);
    }
  }

  if (!t && process.env.AZ_REFRESH_DEFAULT) {
    console.log('[ensureToken] Kein token.json, refreshe über ENV…');
    const refreshed = await azureClient.refresh(process.env.AZ_REFRESH_DEFAULT);
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(refreshed, null, 2));
    t = refreshed;
  }

  if (!t || !t.access_token) {
    throw new Error('Kein Outlook-Konto verbunden');
  }

  const now = Math.floor(Date.now() / 1000);
  const exp = t.expires_at || (now + 60);
  if ((exp - now) < 300 && t.refresh_token) {
    console.log('[ensureToken] Token läuft bald ab, refreshe…');
    const refreshed = await azureClient.refresh(t.refresh_token);
    fs.writeFileSync(TOKEN_FILE, JSON.stringify(refreshed, null, 2));
    return refreshed.access_token;
  }

  return t.access_token;
}

// -----------------------------------------
// Helpers (Normalisierung von Datum/Zeit)
// -----------------------------------------
function normalizeTime(input) {
  if (!input) return null;
  let s = String(input).trim().toLowerCase();

  const hasPM = /pm/.test(s);
  const hasAM = /am/.test(s);

  s = s
    .replace(/uhr/g, '')
    .replace(/\s+/g, '')
    .replace(/[^\d:]/g, ':')
    .replace(/:+/g, ':')
    .replace(/^:|:$/g, '');

  const m = s.match(/^(\d{1,2})(?::(\d{1,2}))?$/);
  if (!m) return null;

  let hh = parseInt(m[1], 10);
  let mm = m[2] ? parseInt(m[2], 10) : 0;

  if (hasPM && hh < 12) hh += 12;
  if (hasAM && hh === 12) hh = 0;

  if (hh < 0 || hh > 23 || mm < 0 || mm > 59) return null;
  return `${String(hh).padStart(2, '0')}:${String(mm).padStart(2, '0')}`;
}

function normalizeDate(input) {
  if (!input) return null;
  const s = String(input).trim();
  let d = s.replace(/\./g, '-').replace(/\//g, '-');
  const m = d.match(/^(\d{4})-(\d{1,2})-(\d{1,2})$/);
  if (!m) return null;
  const yyyy = m[1], mm = m[2].padStart(2, '0'), dd = m[3].padStart(2, '0');
  const iso = `${yyyy}-${mm}-${dd}`;
  const test = new Date(`${iso}T00:00:00`);
  if (Number.isNaN(test.getTime())) return null;
  return iso;
}

function parseTimeslot(dateStr, timeStr, durationMin = 30) {
  const d = normalizeDate(dateStr);
  const t = normalizeTime(timeStr);
  if (!d || !t) {
    const err = new Error('invalid_date_time');
    err.code = 'INVALID_DATE_TIME';
    throw err;
  }
  const start = new Date(`${d}T${t}:00`);
  if (Number.isNaN(start.getTime())) {
    const err = new Error('invalid_date_time');
    err.code = 'INVALID_DATE_TIME';
    throw err;
  }
  const end = new Date(start.getTime() + Number(durationMin || 30) * 60000);
  return { start, end };
}

// -----------------------------------------
// Debug Routes
// -----------------------------------------
app.get('/debug/status', (_req, res) => {
  try {
    if (!fs.existsSync(TOKEN_FILE)) {
      return res.json({
        ok: true,
        hasTokenFile: false,
        hasAZ_REFRESH_DEFAULT: !!process.env.AZ_REFRESH_DEFAULT
      });
    }
    const t = JSON.parse(fs.readFileSync(TOKEN_FILE, 'utf8'));
    res.json({
      ok: true,
      hasTokenFile: true,
      expires_at: t.expires_at,
      hasRefresh: !!t.refresh_token,
      scope: t.scope
    });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/debug/secret', (req, res) => {
  const envSecret = process.env.VAPI_SECRET || '';
  const header = req.get('x-vapi-secret') || req.get('X-Vapi-Secret') || '';
  const auth = req.get('authorization') || req.get('Authorization') || '';
  let bearer = null;
  if (auth && /^bearer\s+/i.test(auth)) bearer = auth.replace(/^bearer\s+/i, '').trim();

  res.json({
    ok: true,
    envHash: envSecret ? crypto.createHash('sha256').update(envSecret).digest('hex').slice(0,8) : null,
    headerHash: header ? crypto.createHash('sha256').update(header).digest('hex').slice(0,8) : null,
    bearerHash: bearer ? crypto.createHash('sha256').update(bearer).digest('hex').slice(0,8) : null
  });
});

app.get('/debug/me', async (_req, res) => {
  try {
    const token = await ensureAzureAccessToken();
    const r = await fetch('https://graph.microsoft.com/v1.0/me', {
      headers: { Authorization: `Bearer ${token}` }
    });
    const body = await r.json();
    res.status(r.status).json({ ok: r.ok, status: r.status, body });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/debug/calendar', async (req, res) => {
  try {
    const { date, time, dur = 30, timezone = 'Europe/Zurich' } = req.query;
    const { start, end } = parseTimeslot(date, time, Number(dur));
    const token = await ensureAzureAccessToken();

    const q = `https://graph.microsoft.com/v1.0/me/calendarView` +
              `?startDateTime=${encodeURIComponent(start.toISOString())}` +
              `&endDateTime=${encodeURIComponent(end.toISOString())}` +
              `&$top=50&$select=subject,organizer,start,end`;

    const r = await fetch(q, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        Prefer: `outlook.timezone="${timezone}"`
      }
    });
    const body = await r.json();
    res.status(r.status).json({ ok: r.ok, status: r.status, body });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

// -----------------------------------------
// Vapi Webhook
// -----------------------------------------
app.post('/vapi-webhook', requireVapiSecret, async (req, res) => {
  try {
    // 1) Intent ermitteln (Header/Body)
    let intent =
      req.body?.intent ||
      req.get('x-vapi-intent') ||
      req.body?.name ||
      null;

    // Nur unsere Tool-Intents verarbeiten, alles andere ignorieren
    const allowed = new Set(['check_availability','create_appointment']);
    if (!allowed.has(intent)) {
      return res.json({ ok: true, ignored: true });
    }

    // 2) Daten normalisieren
    let data = req.body?.data && typeof req.body.data === 'object' ? req.body.data : {};

    // a) Nur message-Wrapper? -> herausziehen
    if (!Object.keys(data).length && req.body?.message) {
      const m = req.body.message;
      data = m?.input || m?.arguments || m || {};
      if (!intent) intent = m?.tool || m?.name || intent;
    }

    // b) Flat payload auf top-level?
    if (!Object.keys(data).length) {
      const { intent: _i, data: _d, message: _m, ...maybeFlat } = req.body || {};
      if (maybeFlat.date || maybeFlat.time || maybeFlat.timezone) data = maybeFlat;
    }

    if (!intent) intent = 'check_availability';

    const timezone = data.timezone || 'Europe/Zurich';
    const duration = Number(data.durationMinutes || 30);

    // Pflichtfelder
    if ((intent === 'check_availability' || intent === 'create_appointment') &&
        (!data.date || !data.time || !timezone)) {
      console.log('[WEBHOOK] missing_fields', { intent, need: ['date','time','timezone'], got: Object.keys(data || {}) });
      return res.status(400).json({
        ok: false,
        error: 'missing_fields',
        need: ['date','time','timezone'],
        got: Object.keys(data || {})
      });
    }

    console.log('[WEBHOOK] tool-call intent:', intent, 'keys:', Object.keys(data || {}));

    const token = await ensureAzureAccessToken();

    let start, end, startISO, endISO;
    try {
      ({ start, end } = parseTimeslot(data.date, data.time, duration));
      startISO = start.toISOString();
      endISO   = end.toISOString();
    } catch (e) {
      if (e.code === 'INVALID_DATE_TIME') {
        return res.status(400).json({
          ok: false,
          error: 'invalid_date_time',
          hint: 'Erwarte date=YYYY-MM-DD und time=HH:mm (z.B. 15:00)',
          got: { date: data.date, time: data.time }
        });
      }
      throw e;
    }

    // --- check_availability ---
    if (intent === 'check_availability') {
      const q = `https://graph.microsoft.com/v1.0/me/calendarView` +
                `?startDateTime=${encodeURIComponent(startISO)}` +
                `&endDateTime=${encodeURIComponent(endISO)}` +
                `&$top=50&$select=subject,organizer,start,end`;

      const r = await fetch(q, {
        headers: {
          Authorization: `Bearer ${token}`,
          Accept: 'application/json',
          Prefer: `outlook.timezone="${timezone}"`
        }
      });

      const raw = await r.text();
      let body = null;
      try { body = raw ? JSON.parse(raw) : null; } catch {
        return res.status(r.status || 500).json({
          ok: false,
          error: 'graph_non_json_response',
          status: r.status,
          preview: raw?.slice(0, 500)
        });
      }

      if (!r.ok) {
        return res.status(r.status).json({ ok: false, error: body?.error || body || 'graph_error', status: r.status });
      }

      const events = Array.isArray(body.value) ? body.value : [];
      const isBusy = events.length > 0;
      return res.json({ ok: true, available: !isBusy, events });
    }

    // --- create_appointment ---
    if (intent === 'create_appointment') {
      const createUrl = 'https://graph.microsoft.com/v1.0/me/events';
      const event = {
        subject: `Besichtigung: ${data.property_id || 'Objekt'}`,
        body: {
          contentType: 'HTML',
          content: `Kontakt: ${data.customer_name || ''} ${data.phone || ''} ${data.email || ''} ${data.notes || ''}`
        },
        start: { dateTime: startISO, timeZone: timezone },
        end:   { dateTime: endISO,  timeZone: timezone },
        attendees: data.email
          ? [{ emailAddress: { address: data.email, name: data.customer_name || '' }, type: 'required' }]
          : []
      };

      const r = await fetch(createUrl, {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          Accept: 'application/json',
          Prefer: `outlook.timezone="${timezone}"`
        },
        body: JSON.stringify(event)
      });

      const raw = await r.text();
      let created = null;
      try { created = raw ? JSON.parse(raw) : null; } catch {}

      if (!r.ok) {
        return res.status(r.status).json({ ok: false, error: created || raw || 'graph_create_error', status: r.status });
      }

      return res.json({ ok: true, created });
    }

    return res.json({ ok: false, error: 'intent_not_supported' });
  } catch (e) {
    console.error('Webhook error', e);
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  }
});

// -----------------------------------------
// Health & Route Listing
// -----------------------------------------
app.get('/', (_req, res) => res.send('Vapi Outlook Middleware running'));

(function logRoutes(app) {
  const routes = [];
  (app._router?.stack || []).forEach((layer) => {
    if (layer.route && layer.route.path) {
      const method = Object.keys(layer.route.methods)[0]?.toUpperCase();
      routes.push(`${method} ${layer.route.path}`);
    }
  });
  console.log('[ROUTES]', routes);
})(app);

// -----------------------------------------
// Start
// -----------------------------------------
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log('Server listening on', PORT));


