// server.js
// All-Origins style proxy with a simple monitoring UI + in-memory stats.
// Node >= 18 is required for global fetch.

const express = require('express');
const rateLimit = require('express-rate-limit');
const { URL } = require('url');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Tunables (env override)
const MAX_CONTENT_LENGTH = parseInt(process.env.MAX_CONTENT_LENGTH || (50 * 1024 * 1024)); // 50 MB
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS || (30 * 1000)); // 30s

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true }));

// Basic rate limiting (per IP)
const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: process.env.RATE_LIMIT_MAX ? parseInt(process.env.RATE_LIMIT_MAX) : 120,
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Always allow CORS from any origin (this is the point)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,User-Agent,Range,If-Modified-Since,If-None-Match');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

/* ----------------- In-memory stats ----------------- */
const stats = {
  startTime: Date.now(),
  totalRequests: 0,
  totalSuccess: 0,
  totalFailed: 0,
  totalBytes: 0,
  requestsByIP: {},      // ip -> count
  domains: {},           // domain -> {count, bytes}
  recent: []             // array of last N requests
};
const RECENT_MAX = 300;

function recordRecent(entry){
  stats.recent.unshift(entry);
  if(stats.recent.length > RECENT_MAX) stats.recent.length = RECENT_MAX;
}

/* ----------------- Helpers ----------------- */

function normalizeTargetUrl(raw) {
  if (!raw) return null;
  try {
    const u = new URL(raw);
    if (!['http:', 'https:'].includes(u.protocol)) return null;
    return u.toString();
  } catch (e) {
    return null;
  }
}

function domainFromUrl(raw){
  try{
    const u = new URL(raw);
    return u.hostname.replace(/^www\./, '');
  }catch(e){
    return '(invalid)';
  }
}

function forwardRequestHeaders(req){
  const forwardHeaders = {};
  const allowed = ['user-agent', 'accept', 'accept-language', 'range'];
  allowed.forEach(h => {
    if (req.headers[h]) forwardHeaders[h] = req.headers[h];
  });
  return forwardHeaders;
}

/* ----------------- Monitoring API ----------------- */

// Simple summary
app.get('/api/stats', (req, res) => {
  const topDomains = Object.entries(stats.domains)
    .sort((a,b)=>b[1].count - a[1].count)
    .slice(0, 20)
    .map(([domain, data]) => ({ domain, count: data.count, bytes: data.bytes }));
  res.json({
    uptimeMs: Date.now() - stats.startTime,
    totalRequests: stats.totalRequests,
    totalSuccess: stats.totalSuccess,
    totalFailed: stats.totalFailed,
    totalBytes: stats.totalBytes,
    requestsByIP: stats.requestsByIP,
    topDomains,
    recentCount: stats.recent.length
  });
});

app.get('/api/recent', (req, res) => {
  res.json(stats.recent.slice(0, RECENT_MAX));
});

app.get('/api/top', (req, res) => {
  const limit = Math.min(100, parseInt(String(req.query.limit || '20')));
  const list = Object.entries(stats.domains)
    .sort((a,b)=>b[1].count - a[1].count)
    .slice(0, limit)
    .map(([domain, data]) => ({ domain, count: data.count, bytes: data.bytes }));
  res.json(list);
});

// Clear stats (no auth) — convenient for local use only
app.post('/api/clear', (req, res) => {
  stats.totalRequests = 0;
  stats.totalSuccess = 0;
  stats.totalFailed = 0;
  stats.totalBytes = 0;
  stats.requestsByIP = {};
  stats.domains = {};
  stats.recent = [];
  stats.startTime = Date.now();
  res.json({ ok: true });
});

/* ----------------- Static UI ----------------- */
app.use('/', express.static(path.join(__dirname, 'public')));

/* ----------------- Proxy endpoint ----------------- */

/**
 * GET /fetch?url=...
 * POST /fetch { "url": "..." }
 */
app.all('/fetch', async (req, res) => {
  const rawUrl = (req.method === 'GET') ? req.query.url : (req.body && req.body.url);
  const target = normalizeTargetUrl(rawUrl);

  const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
  stats.totalRequests++;
  stats.requestsByIP[clientIp] = (stats.requestsByIP[clientIp] || 0) + 1;
  const start = Date.now();

  if (!target) {
    stats.totalFailed++;
    const entry = { ts: new Date().toISOString(), ip: clientIp, url: rawUrl, domain: '(invalid)', status: 400, bytes: 0, durationMs: Date.now()-start, error: 'invalid_url' };
    recordRecent(entry);
    return res.status(400).send('Missing or invalid "url" parameter (must be http(s) URL).');
  }

  // Prepare headers to forward
  const forwardHeaders = forwardRequestHeaders(req);

  // Abort support for upstream timeout
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);

  try {
    const upstream = await fetch(target, {
      method: 'GET',
      headers: forwardHeaders,
      redirect: 'follow',
      signal: controller.signal
    });
    clearTimeout(timeout);

    // Respect max content-length if upstream provides it
    const cl = upstream.headers.get('content-length');
    if (cl && parseInt(cl) > MAX_CONTENT_LENGTH) {
      stats.totalFailed++;
      const entry = { ts: new Date().toISOString(), ip: clientIp, url: target, domain: domainFromUrl(target), status: 413, bytes: 0, durationMs: Date.now()-start, error: 'upstream_too_large' };
      recordRecent(entry);
      return res.status(413).send('Upstream resource too large.');
    }

    // Forward selected headers
    const headersToCopy = ['content-type', 'content-length', 'cache-control', 'content-disposition', 'last-modified', 'etag', 'accept-ranges'];
    headersToCopy.forEach(h => {
      const v = upstream.headers.get(h);
      if (v) res.setHeader(h, v);
    });

    // Set CORS (middleware already set it, set again to be safe)
    res.setHeader('Access-Control-Allow-Origin', '*');

    // Status code passthrough
    res.status(upstream.status);

    // Stream upstream -> client while tracking bytes
    const upstreamBody = upstream.body;
    if (!upstreamBody) {
      stats.totalFailed++;
      const entry = { ts: new Date().toISOString(), ip: clientIp, url: target, domain: domainFromUrl(target), status: upstream.status || 204, bytes: 0, durationMs: Date.now()-start, error: 'no_body' };
      recordRecent(entry);
      return res.sendStatus(upstream.status || 204);
    }

    // Track bytes streaming
    let bytes = 0;
    let ended = false;

    upstreamBody.on('data', chunk => {
      bytes += chunk.length;
      // enforce guard — abort everything if too big
      if (bytes > MAX_CONTENT_LENGTH) {
        try { controller.abort(); } catch (e) {}
        // will trigger catch / close
      }
    });

    upstreamBody.on('error', err => {
      if (!ended) {
        ended = true;
        stats.totalFailed++;
        const entry = { ts: new Date().toISOString(), ip: clientIp, url: target, domain: domainFromUrl(target), status: 500, bytes, durationMs: Date.now()-start, error: 'stream_error' };
        recordRecent(entry);
        try { res.end(); } catch(e){}
      }
    });

    upstreamBody.on('end', () => {
      if (!ended) {
        ended = true;
        stats.totalSuccess++;
        stats.totalBytes += bytes;
        const domain = domainFromUrl(target);
        if (!stats.domains[domain]) stats.domains[domain] = { count: 0, bytes: 0 };
        stats.domains[domain].count++;
        stats.domains[domain].bytes += bytes;
        const entry = { ts: new Date().toISOString(), ip: clientIp, url: target, domain, status: upstream.status, bytes, durationMs: Date.now()-start };
        recordRecent(entry);
      }
    });

    // pipe stream
    upstreamBody.pipe(res);
  } catch (err) {
    clearTimeout(timeout);
    stats.totalFailed++;
    const domain = domainFromUrl(target);
    const dur = Date.now() - start;
    const entry = { ts: new Date().toISOString(), ip: clientIp, url: target, domain, status: 500, bytes: 0, durationMs: dur, error: err.name || String(err) };
    recordRecent(entry);
    if (err.name === 'AbortError') {
      return res.status(504).send('Upstream timed out or aborted.');
    }
    console.error('Fetch error:', err);
    return res.status(500).send('Proxy fetch failed: ' + String(err && err.message ? err.message : err));
  }
});

/* ----------------- Root info when static not found ----------------- */
app.use((req,res,next) => {
  // If static UI exists, it will be served. If not, respond with a helpful message.
  if (req.path.startsWith('/api') || req.path === '/fetch') return next();
  res.setHeader('Content-Type','text/plain');
  res.send('All-Origins Proxy with monitor\nUse /fetch?url=... or POST { "url": "..." }\nAPI: /api/stats, /api/recent, /api/top\nStatic UI served from / (public/index.html)');
});

/* ----------------- Start ----------------- */
app.listen(PORT, () => {
  console.log(`All-origins proxy with monitor listening on http://0.0.0.0:${PORT}`);
});