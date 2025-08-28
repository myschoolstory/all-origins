// server.js
const express = require('express');
const rateLimit = require('express-rate-limit');
const { URL } = require('url');

const app = express();
const PORT = process.env.PORT || 3000;

// Tunables
const MAX_CONTENT_LENGTH = parseInt(process.env.MAX_CONTENT_LENGTH || (50 * 1024 * 1024)); // 50 MB
const REQUEST_TIMEOUT_MS = parseInt(process.env.REQUEST_TIMEOUT_MS || (30 * 1000)); // 30s

app.use(express.json({ limit: '1mb' }));

// Basic rate limiting to reduce abuse
const limiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: process.env.RATE_LIMIT_MAX ? parseInt(process.env.RATE_LIMIT_MAX) : 60, // 60 requests per minute per IP
  standardHeaders: true,
  legacyHeaders: false
});
app.use(limiter);

// Always allow CORS from any origin (the whole point)
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  // allow common headers for browser fetches
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,User-Agent,Range,If-Modified-Since,If-None-Match');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

/**
 * Helper: validate and normalize target URL
 */
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

/**
 * GET /fetch?url=...
 * POST /fetch   { "url": "..." }
 *
 * Returns the upstream response body and forwards some useful headers, while setting CORS headers.
 */
app.all('/fetch', async (req, res) => {
  const rawUrl = (req.method === 'GET') ? req.query.url : (req.body && req.body.url);
  const target = normalizeTargetUrl(rawUrl);

  if (!target) {
    return res.status(400).send('Missing or invalid "url" parameter (must be http(s) URL).');
  }

  // Forward a small set of client headers that help upstreams (but do not forward sensitive headers).
  const forwardHeaders = {};
  const allowed = ['user-agent', 'accept', 'accept-language', 'range'];
  allowed.forEach(h => {
    if (req.headers[h]) forwardHeaders[h] = req.headers[h];
  });

  // Use Node's global fetch (Node 18+). We follow redirects.
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

    // If upstream provided content-length and it exceeds our configured max, reject to avoid huge downloads
    const cl = upstream.headers.get('content-length');
    if (cl && parseInt(cl) > MAX_CONTENT_LENGTH) {
      return res.status(413).send('Upstream resource too large.');
    }

    // Copy a safe subset of headers back to the client
    const headersToCopy = ['content-type', 'content-length', 'cache-control', 'content-disposition', 'last-modified', 'etag', 'accept-ranges'];
    headersToCopy.forEach(h => {
      const v = upstream.headers.get(h);
      if (v) res.setHeader(h, v);
    });

    // Make sure CORS header is present (middleware already set it)
    res.status(upstream.status);

    // Stream upstream body -> client, with a simple size guard
    const upstreamBody = upstream.body;
    if (!upstreamBody) {
      return res.sendStatus(204);
    }

    let bytes = 0;
    const MAX = MAX_CONTENT_LENGTH;

    upstreamBody.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > MAX) {
        // abort upstream and end response
        try { controller.abort(); } catch (e) {}
        try { res.end(); } catch (e) {}
      }
    });

    upstreamBody.on('error', (err) => {
      console.error('Upstream stream error', err);
      try { res.end(); } catch (e) {}
    });

    // Pipe the stream
    upstreamBody.pipe(res);
  } catch (err) {
    clearTimeout(timeout);
    if (err.name === 'AbortError') {
      return res.status(504).send('Upstream timed out or aborted.');
    }
    console.error('Fetch error:', err);
    return res.status(500).send('Proxy fetch failed: ' + String(err && err.message ? err.message : err));
  }
});

app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/plain');
  res.send('All-Origins CORS Proxy\nUse /fetch?url=... or POST { "url": "..." }\nWarning: open proxy — secure before exposing publicly.');
});

app.listen(PORT, () => {
  console.log(`All-origins proxy listening on http://localhost:${PORT}`);
  console.log(`Example usage: http://localhost:${PORT}/fetch?url=https://example.com/image.jpg`);
});