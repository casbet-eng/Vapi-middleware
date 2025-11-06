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

const app = express();
app.use(bodyParser.json());

// -----------------------------------------
// Settings & files
// -----------------------------------------
const TOKEN_FILE = path.join(__dirname, 'token.json'); // Persistenter Tokenstore
const SCOPES = ['offline_access', 'openid', 'profile', 'email', 'Calendars.ReadWrite'];

let azureClient;

// -----------------------------------------
// Helper: strict secret header (optional)
// -----------------------------------------
function requireVapiSecret(req, res, next) {
  if (!process.env.VAPI_SECRET) return next();
  const val = req.get('x-vapi-secret');
  if (val && val === process.env.VAPI_SECRET) return next();
  return res.status(401).json({ ok: false, error: 'unauthorized' });
}

// -----------------------------------------
// Bootstrap: Falls kein token.json -> über ENV refreshen
// (WICHTIG: erst aufrufen, wenn azureClient gesetzt ist!)
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

    // 👉 WICHTIG: Bootstrap ERST JETZT, wenn azureClient existiert
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

    // Persistieren
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
// Helpers
// -----------------------------------------
function parseTimeslot(dateStr, timeStr, durationMin = 30) {
  if (!dateStr || !timeStr) throw new Error('date/time fehlen');
  const start = new Date(`${dateStr}T${timeStr}:00`);
  const end = new Date(start.getTime() + durationMin * 60 * 1000);
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

    // c) Falls weiterhin kein Intent & keine Daten: Event-Spam ignorieren
    if (!intent && !Object.keys(data).length) {
      console.log('[WEBHOOK] ignore non-tool event, keys:', Object.keys(req.body || {}));
      return res.json({ ok: true, ignored: true });
    }

    if (!intent) intent = 'check_availability';

    const timezone = data.timezone || 'Europe/Zurich';
    const duration = Number(data.durationMinutes || 30);

    // Pflichtfelder bei unseren Intents
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
    const { start, end } = parseTimeslot(data.date, data.time, duration);
    const startISO = start.toISOString();
    const endISO   = end.toISOString();

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

