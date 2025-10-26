// server.js — Outlook-only Vapi Middleware
require('dotenv').config();
process.on('unhandledRejection', (e) => { console.error('UNHANDLED REJECTION', e); });
process.on('uncaughtException', (e) => { console.error('UNCAUGHT EXCEPTION', e); });
console.log('Booting server.js ...');
const express = require('express');
const bodyParser = require('body-parser');
const fetch = require('node-fetch'); // v2.x in package.json!
const OpenID = require('openid-client');
const { Issuer } = OpenID;
if (!Issuer || typeof Issuer.discover !== 'function') {
  console.error('openid-client Importproblem: Issuer.discover fehlt');
}
const fs = require('fs');

const app = express();
app.use(bodyParser.json());

// ---------- simple JSON token store (multi-tenant) ----------
const TOKENS_PATH = process.env.TOKENS_PATH || './tokens.json';
function readStore() {
  try { return JSON.parse(fs.readFileSync(TOKENS_PATH, 'utf8')); }
  catch { return {}; }
}
function writeStore(obj) {
  fs.writeFileSync(TOKENS_PATH, JSON.stringify(obj, null, 2));
}
function getTenant(tenantId) {
  const store = readStore();
  return store[tenantId] || null;
}
function upsertTenant(tenantId, data) {
  const store = readStore();
  store[tenantId] = { ...(store[tenantId] || {}), ...data };
  writeStore(store);
}

// Optional: simple auth for incoming webhooks (set VAPI_SECRET in Render)
function requireVapiSecret(req, res, next) {
  if (!process.env.VAPI_SECRET) return next();
  const header = req.get('x-vapi-secret');
  if (header && header === process.env.VAPI_SECRET) return next();
  return res.status(401).json({ ok: false, error: 'unauthorized' });
}

// ---------- Azure / Microsoft Graph OAuth client ----------
let azureClient;
async function initAzure() {
  if (!process.env.AZ_TENANT_ID || !process.env.AZ_CLIENT_ID || !process.env.AZ_CLIENT_SECRET || !process.env.AZ_REDIRECT_URI) {
    console.warn('Azure ENV Variablen fehlen. Setze AZ_TENANT_ID, AZ_CLIENT_ID, AZ_CLIENT_SECRET, AZ_REDIRECT_URI');
    return;
  }
  const issuer = await Issuer.discover(`https://login.microsoftonline.com/${process.env.AZ_TENANT_ID}/v2.0`);
  azureClient = new issuer.Client({
    client_id: process.env.AZ_CLIENT_ID,
    client_secret: process.env.AZ_CLIENT_SECRET,
    redirect_uris: [process.env.AZ_REDIRECT_URI],
    response_types: ['code']
  });
  console.log('Azure OIDC client initialisiert.');
}
initAzure().catch(e => console.error('Azure init error', e));

const SCOPES = ['offline_access', 'Calendars.ReadWrite'];

// ---------- OAuth routes ----------
app.get('/auth/azure', async (req, res) => {
  try {
    if (!azureClient) return res.status(500).send('Azure nicht konfiguriert.');
    const tenantId = req.query.tenant || 'default';
    const url = azureClient.authorizationUrl({
      scope: SCOPES.join(' '),
      response_mode: 'query',
      state: tenantId
    });
    res.redirect(url);
  } catch (e) {
    console.error(e);
    res.status(500).send('Auth start error');
  }
});

app.get('/auth/azure/callback', async (req, res) => {
  try {
    const params = azureClient.callbackParams(req);
    const tenantId = params.state || 'default';
    const tokenSet = await azureClient.callback(process.env.AZ_REDIRECT_URI, params);

    upsertTenant(tenantId, {
      type: 'azure',
      access_token: tokenSet.access_token,
      refresh_token: tokenSet.refresh_token,
      scope: tokenSet.scope,
      expires_at: tokenSet.expires_at || (Date.now() + 45 * 60 * 1000)
    });

    res.send('Microsoft Outlook verbunden. Du kannst dieses Fenster schließen.');
  } catch (e) {
    console.error('Azure callback error', e);
    res.status(500).send('Azure callback error');
  }
});

// ---------- token refresh ----------
async function ensureAzureAccessToken(tenantId) {
  const t = getTenant(tenantId);
  if (!t || t.type !== 'azure' || !t.refresh_token) throw new Error('Kein Outlook-Konto verbunden');

  // Refresh wenn abgelaufen/kurz davor
  if (!t.expires_at || Date.now() > (t.expires_at - 60 * 1000)) {
    const tokenUrl = `https://login.microsoftonline.com/${process.env.AZ_TENANT_ID}/oauth2/v2.0/token`;
    const params = new URLSearchParams();
    params.append('client_id', process.env.AZ_CLIENT_ID);
    params.append('client_secret', process.env.AZ_CLIENT_SECRET);
    params.append('grant_type', 'refresh_token');
    params.append('refresh_token', t.refresh_token);
    params.append('scope', SCOPES.join(' '));

    const resp = await fetch(tokenUrl, { method: 'POST', body: params });
    const data = await resp.json();
    if (!resp.ok || data.error) {
      throw new Error(`Token refresh failed: ${resp.status} ${JSON.stringify(data)}`);
    }
    upsertTenant(tenantId, {
      access_token: data.access_token,
      refresh_token: data.refresh_token || t.refresh_token,
      expires_at: Date.now() + (data.expires_in * 1000)
    });
  }
  return getTenant(tenantId).access_token;
}

// ---------- helpers ----------
function parseTimeslot(dateStr, timeStr, durationMin = 30) {
  if (!dateStr || !timeStr) throw new Error('date/time fehlen');
  const start = new Date(`${dateStr}T${timeStr}:00`);
  const end = new Date(start.getTime() + durationMin * 60 * 1000);
  return { start, end };
}

// ---------- Vapi webhook ----------
app.post('/vapi-webhook', requireVapiSecret, async (req, res) => {
  try {
    const { intent, data = {}, meta = {} } = req.body || {};
    if (!intent) return res.status(400).json({ ok: false, error: 'intent missing' });

    const tenantId = data.tenant || 'default';
    const timezone = data.timezone || 'Europe/Zurich';
    const duration = Number(data.durationMinutes || 30);

    if (intent === 'check_availability' || intent === 'create_appointment') {
      const token = await ensureAzureAccessToken(tenantId);
      const { start, end } = parseTimeslot(data.date, data.time, duration);
      const startISO = start.toISOString();
      const endISO = end.toISOString();

      if (intent === 'check_availability') {
        const q = `https://graph.microsoft.com/v1.0/me/calendarView?startDateTime=${encodeURIComponent(startISO)}&endDateTime=${encodeURIComponent(endISO)}`;
        const r = await fetch(q, { headers: { Authorization: `Bearer ${token}` } });
        const body = await r.json();
        const isBusy = Array.isArray(body.value) && body.value.length > 0;
        return res.json({ ok: true, available: !isBusy, events: body.value || [] });
      }

      if (intent === 'create_appointment') {
        const createUrl = 'https://graph.microsoft.com/v1.0/me/events';
        const event = {
          subject: `Besichtigung: ${data.property_id || 'Objekt'}`,
          body: { contentType: 'HTML', content: `Kontakt: ${data.customer_name || ''} ${data.phone || meta.caller_number || ''} ${data.email || ''}` },
          start: { dateTime: startISO, timeZone: timezone },
          end: { dateTime: endISO, timeZone: timezone },
          attendees: data.email ? [{ emailAddress: { address: data.email, name: data.customer_name || '' }, type: 'required' }] : []
        };
        const r = await fetch(createUrl, {
          method: 'POST',
          headers: { Authorization: `Bearer ${token}`, 'Content-Type': 'application/json' },
          body: JSON.stringify(event)
        });
        const created = await r.json();
        if (!r.ok) return res.status(400).json({ ok: false, error: created });
        return res.json({ ok: true, created });
      }
    }

    return res.json({ ok: false, error: 'intent_not_supported' });
  } catch (e) {
    console.error('Webhook error', e);
    return res.status(500).json({ ok: false, error: e.message || String(e) });
  }
});

// ---------- health ----------
app.get('/', (_req, res) => res.send('Vapi Outlook Middleware running'));

// ---------- start ----------
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Server listening on', PORT));


