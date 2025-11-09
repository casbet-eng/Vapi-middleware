// server.js — Vapi Middleware (Outlook only) — Multi-Tenant ready
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
// Settings & scopes
// -----------------------------------------
const SCOPES = ['offline_access', 'openid', 'profile', 'email', 'Calendars.ReadWrite'];

// -----------------------------------------
// Helper: strict secret header (robust + sanitized)
// -----------------------------------------
function clean(v) { return String(v || '').trim(); }
function hash8(v) { return crypto.createHash('sha256').update(String(v || '')).digest('hex').slice(0, 8); }

/**
 * Liest eingehendes Secret aus mehreren möglichen Quellen
 * und entfernt führende ", " oder Spaces, die Vapi gelegentlich mitschickt.
 */
function extractIncomingSecret(req) {
  // 1) Bevorzugt: x-vapi-secret
  const headerRaw = req.get('x-vapi-secret') || req.get('X-Vapi-Secret');

  // 2) Fallback: Authorization: Bearer <token>
  const auth = req.get('authorization') || req.get('Authorization');
  let bearer = null;
  if (auth && /^bearer\s+/i.test(auth)) {
    bearer = auth.replace(/^bearer\s+/i, '').trim();
  }

  // 3) Weitere Fallbacks
  const xApiKey = req.get('x-api-key') || req.get('X-Api-Key');
  const q = req.query?.secret;
  const b = req.body?.secret;

  // Reihenfolge: header > bearer > x-api-key > query > body
  let candidate = clean(headerRaw || bearer || xApiKey || q || b || '');

  // **Fix:** Vapi schickt teils ein führendes ", " mit – hier hart entfernen.
  candidate = candidate.replace(/^[,\s]+/, '');

  return {
    candidate,
    sources: { header: !!headerRaw, bearer: !!bearer, xApiKey: !!xApiKey, query: !!q, body: !!b },
    raw: { headerRaw, bearer, xApiKey, q, b }
  };
}

function requireVapiSecret(req, res, next) {
  const envSecret = clean(process.env.VAPI_SECRET || '');
  if (!envSecret) return next(); // Schutz aus, wenn nicht gesetzt

  const { candidate, sources, raw } = extractIncomingSecret(req);
  const ok = !!candidate && candidate === envSecret;

  // Nur kurze, sichere Logs (keine Klartext-Secrets)
  console.log(
    `[AUTH] eq=${ok} hdr=${hash8(raw.headerRaw)} env=${hash8(envSecret)} src=${JSON.stringify(sources)}`
  );

  if (ok) return next();

  console.warn('[AUTH] x-vapi-secret missing/mismatch. Present?:', !!candidate);
  return res.status(401).json({ ok: false, error: 'unauthorized' });
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
// Multi-Tenant Setup
// -----------------------------------------
let TENANTS = [];
const tenantsPath = path.join(__dirname, 'tenants.json');
try {
  TENANTS = JSON.parse(fs.readFileSync(tenantsPath, 'utf8'));
  console.log('[TENANTS] loaded:', TENANTS.map(t => t.id));
} catch (e) {
  console.warn('[TENANTS] tenants.json not found or invalid. Create one next to server.js');
  TENANTS = [];
}

const azureClients = new Map(); // tenantId -> openid-client Client
const tenantMeta   = new Map(); // tenantId -> { token_file, timezone, refresh_env_var }

function getTenantById(id) {
  return TENANTS.find(t => t.id === id);
}
function getTenantByApiKey(key) {
  return TENANTS.find(t => t.api_key && t.api_key === key);
}

function resolveAzField(t, key) {
  const az = t.azure || {};
  const v = az[key];

  // Wenn in tenants.json ein echter Wert steht (und nicht "__ENV__"), nimm ihn direkt
  if (v && v !== '__ENV__') return v;

  // Fallback: passender ENV-Name anhand des Felds
  const envMap = {
    tenant_id: 'AZ_TENANT_ID',
    client_id: 'AZ_CLIENT_ID',
    client_secret: 'AZ_CLIENT_SECRET',
    redirect_uri: 'AZ_REDIRECT_URI'
  };

  return process.env[envMap[key]];
}

// Init Azure client per tenant
async function initAzureForTenant(t) {
  // Felder wahlweise aus tenants.json oder – bei "__ENV__" – aus ENV laden
  const tenant_id     = resolveAzField(t, 'tenant_id');
  const client_id     = resolveAzField(t, 'client_id');
  const client_secret = resolveAzField(t, 'client_secret');
  const redirect_uri  = resolveAzField(t, 'redirect_uri');

  if (!tenant_id || !client_id || !client_secret || !redirect_uri) {
    console.warn(`[Azure] Tenant ${t.id} has incomplete Azure config (tenant_id/client_id/client_secret/redirect_uri).`);
    return;
  }

  const issuer = await Issuer.discover(`https://login.microsoftonline.com/${tenant_id}/v2.0`);
  const client = new issuer.Client({
    client_id,
    client_secret,
    redirect_uris: [redirect_uri],
    response_types: ['code'],
  });

  azureClients.set(t.id, client);
  tenantMeta.set(t.id, {
    token_file: path.resolve(__dirname, (t.azure && t.azure.token_file) || `./tokens/${t.id}.token.json`),
    timezone: t.timezone || 'Europe/Zurich',
    refresh_env_var: (t.azure && t.azure.refresh_env_var) || null
  });

  console.log(`[Azure] OIDC client initialised for tenant=${t.id}`);
}

(async function initAllTenants() {
  for (const t of TENANTS) {
    if (t.disabled) {
      console.log(`[TENANTS] skip disabled tenant=${t.id}`);
      continue;
    }
    try { await initAzureForTenant(t); }
    catch (e) { console.error(`[Azure] Init error tenant=${t.id}`, e); }
  }
})();

// Token helpers per tenant
async function bootstrapTokenFromEnvIfNeeded(tenantId) {
  const meta = tenantMeta.get(tenantId);
  const client = azureClients.get(tenantId);
  if (!meta || !client) return;

  if (fs.existsSync(meta.token_file)) return;

  const envVarName = meta.refresh_env_var;
  const envRefresh = envVarName ? process.env[envVarName] : null;
  if (!envRefresh) return;

  console.log(`[BOOT][${tenantId}] No token file, refreshing via ENV ${envVarName}…`);
  const refreshed = await client.refresh(envRefresh);
  fs.mkdirSync(path.dirname(meta.token_file), { recursive: true });
  fs.writeFileSync(meta.token_file, JSON.stringify(refreshed, null, 2));
  console.log(`[BOOT][${tenantId}] Token saved from ENV refresh.`);
}

async function ensureAzureAccessTokenForTenant(tenantId) {
  const client = azureClients.get(tenantId);
  const meta   = tenantMeta.get(tenantId);
  if (!client || !meta) throw new Error(`Azure Client not initialised for tenant=${tenantId}`);

  if (!fs.existsSync(meta.token_file)) {
    await bootstrapTokenFromEnvIfNeeded(tenantId);
  }

  let t = null;
  if (fs.existsSync(meta.token_file)) {
    try { t = JSON.parse(fs.readFileSync(meta.token_file, 'utf8')); }
    catch (e) { console.error(`[Token][${tenantId}] read failed:`, e); }
  }

  if (!t || !t.access_token) {
    throw new Error(`No Outlook token for tenant=${tenantId}`);
  }

  const now = Math.floor(Date.now()/1000);
  const exp = t.expires_at || (now + 60);
  if ((exp - now) < 300 && t.refresh_token) {
    console.log(`[Token][${tenantId}] expiring soon, refreshing…`);
    const refreshed = await client.refresh(t.refresh_token);
    fs.writeFileSync(meta.token_file, JSON.stringify(refreshed, null, 2));
    return refreshed.access_token;
  }

  return t.access_token;
}

// -----------------------------------------
// Tenant Context Resolver (Header X-Api-Key bevorzugt, sonst body/query tenant_id)
// -----------------------------------------
app.use((req, res, next) => {
  const apiKey = req.get('X-Api-Key') || req.get('x-api-key');
  let tenant = apiKey ? getTenantByApiKey(apiKey) : null;

  if (!tenant) {
    const bodyTenantId = req.body?.tenant_id || req.query?.tenant_id;
    if (bodyTenantId) tenant = getTenantById(bodyTenantId);
  }

  if (tenant) {
    req.tenant = {
      id: tenant.id,
      timezone: tenant.timezone || 'Europe/Zurich',
      provider: tenant.calendar?.provider || 'outlook'
    };
  }
  next();
});

// -----------------------------------------
// OAuth Flows (per tenant)
// -----------------------------------------
app.get('/auth/azure', async (req, res) => {
  try {
    const tenantId = req.query.tenant_id;
    if (!tenantId) return res.status(400).send('tenant_id required');
    const client = azureClients.get(tenantId);
    const t = getTenantById(tenantId);
    if (!client || !t) return res.status(500).send('Tenant/Azure not configured.');

    const state = tenantId; // wichtig: state=tenant
    const url = client.authorizationUrl({
      scope: SCOPES.join(' '),
      response_mode: 'query',
      state
    });
    console.log('[OAUTH] start tenant=', tenantId);
    res.redirect(url);
  } catch (e) {
    console.error('Auth start error', e);
    res.status(500).send('Auth start error');
  }
});

app.get('/auth/azure/callback', async (req, res) => {
  try {
    // Microsoft liefert GET-Query-Params zurück
    const tenantId = req.query.state;
    const client = azureClients.get(tenantId);
    const t = getTenantById(tenantId);
    if (!tenantId || !client || !t) return res.status(400).send('Invalid state/tenant');

    // openid-client akzeptiert die query-params als "params"
    const params = req.query;

    const tokenSet = await client.callback(
      t.azure.redirect_uri,
      params,
      { state: tenantId }
    );

    const meta = tenantMeta.get(tenantId);
    fs.mkdirSync(path.dirname(meta.token_file), { recursive: true });
    fs.writeFileSync(meta.token_file, JSON.stringify(tokenSet, null, 2));
    console.log('[OAUTH] token saved for tenant=', tenantId, 'file=', meta.token_file);

    res.send(`Microsoft Outlook verbunden für Tenant ${tenantId}. Du kannst dieses Fenster schliessen.`);
  } catch (e) {
    console.error('Azure callback error', e);
    res.status(500).send('Azure callback error');
  }
});

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
// Debug Routes (tenant-aware)
// -----------------------------------------
app.get('/debug/status', (req, res) => {
  try {
    const tenantId = req.query.tenant_id;
    if (!tenantId) {
      return res.json({ ok: true, tenants: TENANTS.map(t => t.id) });
    }
    const meta = tenantMeta.get(tenantId);
    if (!meta) return res.status(404).json({ ok: false, error: 'TENANT_UNKNOWN' });

    const exists = fs.existsSync(meta.token_file);
    let t = null;
    if (exists) {
      try { t = JSON.parse(fs.readFileSync(meta.token_file, 'utf8')); } catch {}
    }
    res.json({
      ok: true,
      tenant: tenantId,
      hasTokenFile: exists,
      expires_at: t?.expires_at,
      hasRefresh: !!t?.refresh_token,
      scope: t?.scope
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

app.get('/debug/me', async (req, res) => {
  try {
    const tenantId = req.query.tenant_id || req.tenant?.id;
    if (!tenantId) return res.status(400).json({ ok: false, error: 'TENANT_REQUIRED' });

    const token = await ensureAzureAccessTokenForTenant(tenantId);
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
    const tenantId = req.query.tenant_id || req.tenant?.id;
    if (!tenantId) return res.status(400).json({ ok: false, error: 'TENANT_REQUIRED' });

    const { date, time, dur = 30, timezone } = req.query;
    const { start, end } = parseTimeslot(date, time, Number(dur));
    const token = await ensureAzureAccessTokenForTenant(tenantId);
    const tz = timezone || tenantMeta.get(tenantId)?.timezone || 'Europe/Zurich';

    const q = `https://graph.microsoft.com/v1.0/me/calendarView` +
              `?startDateTime=${encodeURIComponent(start.toISOString())}` +
              `&endDateTime=${encodeURIComponent(end.toISOString())}` +
              `&$top=50&$select=subject,organizer,start,end`;

    const r = await fetch(q, {
      headers: {
        Authorization: `Bearer ${token}`,
        Accept: 'application/json',
        Prefer: `outlook.timezone="${tz}"`
      }
    });
    const body = await r.json();
    res.status(r.status).json({ ok: r.ok, status: r.status, body });
  } catch (e) {
    res.status(500).json({ ok: false, error: e.message });
  }
});

app.get('/debug/tenants', (_req, res) => {
  res.json({
    loadedFrom: path.join(__dirname, 'tenants.json'),
    tenants: TENANTS.map(t => ({ id: t.id, disabled: !!t.disabled })),
    initialisedTenants: {
      azureClients: Array.from(azureClients.keys()),
      tenantMeta:   Array.from(tenantMeta.keys())
    }
  });
});

app.get('/debug/env-presence', (_req, res) => {
  res.json({
    AZ_TENANT_ID: !!process.env.AZ_TENANT_ID,
    AZ_CLIENT_ID: !!process.env.AZ_CLIENT_ID,
    AZ_CLIENT_SECRET: !!process.env.AZ_CLIENT_SECRET,
    AZ_REDIRECT_URI: !!process.env.AZ_REDIRECT_URI,
    AZ_REFRESH_DEFAULT: !!process.env.AZ_REFRESH_DEFAULT
  });
});

// -----------------------------------------
// Vapi Webhook (tenant-aware)
// -----------------------------------------
app.post('/vapi-webhook', requireVapiSecret, async (req, res) => {
  try {
    if (!req.tenant) {
      return res.status(400).json({ ok: false, error: 'TENANT_REQUIRED' });
    }

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

    const timezone = data.timezone || req.tenant.timezone || 'Europe/Zurich';
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

    console.log('[WEBHOOK] tool-call intent:', intent, 'tenant:', req.tenant.id, 'keys:', Object.keys(data || {}));

    const token = await ensureAzureAccessTokenForTenant(req.tenant.id);

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
app.get('/', (_req, res) => res.send('Vapi Outlook Middleware (Multi-Tenant) running'));

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


