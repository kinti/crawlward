#!/usr/bin/env node
// crawlward — watchdog for AI crawlers at your own origin.
// Classifies AI crawler traffic from JSONL access logs (Caddy `format json`,
// nginx `log_format ... escape=json`) and Apache combined logs.
// Zero dependencies. Node >= 18.

import { createReadStream, readFileSync, openSync, readSync, closeSync } from 'node:fs';
import { createGunzip } from 'node:zlib';
import { createInterface } from 'node:readline';
import { pathToFileURL } from 'node:url';
import { verifyBots } from './verify.mjs';

const VERSION = '0.2.1';
const REGISTRY_URL = new URL('../registry/crawlers.json', import.meta.url);
const BOTLIKE = /(bot|crawler|spider|slurp|scrap|fetcher)/i;
const MAX_TRACKED_PATHS = 5000;
// Hours are timestamp-derived, not attacker-controlled, but a garbage or
// years-long log can still flood the map — bound it well above any sane
// timespan (100k buckets ≈ 11 years) so peak-rate math stays truthful.
const MAX_TRACKED_HOURS = 100000;
const MAX_UNMATCHED_UAS = 20000;

export function loadRegistry() {
  const raw = JSON.parse(readFileSync(REGISTRY_URL, 'utf8'));
  return raw.crawlers ?? [];
}

// Longest token first, so `GoogleOther-Image` wins over `GoogleOther`.
// Matching is case-insensitive: Meta's wire UA strings are lowercase
// (meta-externalagent/1.1) while docs often print Meta-ExternalAgent.
export function compileMatchers(registry) {
  return [...registry]
    .map((c) => ({ ...c, _lc: c.token.toLowerCase() }))
    .sort((a, b) => b._lc.length - a._lc.length);
}

export function classifyUA(ua, matchers) {
  if (!ua) return null;
  const lc = ua.toLowerCase();
  for (const c of matchers) {
    if (lc.includes(c._lc)) return c;
  }
  return null;
}

function pickHeader(headers, name) {
  if (!headers) return '';
  const v = headers[name] ?? headers[name.toLowerCase()];
  return Array.isArray(v) ? (v[0] ?? '') : typeof v === 'string' ? v : '';
}

function toInt(v) {
  const n = Number(v);
  return Number.isFinite(n) ? n : 0;
}

const MONTHS = {
  Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5,
  Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11,
};

function epochSeconds(n) {
  return n > 1e12 ? n / 1000 : n;
}

function parseTs(raw) {
  if (raw.msec !== undefined) {
    const n = parseFloat(raw.msec);
    return Number.isFinite(n) ? n : null;
  }
  if (typeof raw.timestamp === 'number') return epochSeconds(raw.timestamp);
  if (typeof raw.time === 'number') return epochSeconds(raw.time);
  if (typeof raw.time === 'string' && raw.time) {
    const d = Date.parse(raw.time);
    return Number.isNaN(d) ? null : d / 1000;
  }
  if (typeof raw.time_local === 'string') {
    const m = /^(\d{1,2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+-]\d{4})?$/.exec(raw.time_local);
    if (m && MONTHS[m[2]] !== undefined) {
      const tz = m[7] ?? '+0000';
      const offset = (Number(tz.slice(1, 3)) * 60 + Number(tz.slice(3))) * (tz[0] === '-' ? -1 : 1) * 60000;
      const ms = Date.UTC(+m[3], MONTHS[m[2]], +m[1], +m[4], +m[5], +m[6]) - offset;
      return Number.isNaN(ms) ? null : ms / 1000;
    }
  }
  return null;
}

// Accepts one JSONL record and maps it to a common shape. Understands the
// Caddy `format json` shape and common nginx JSON log formats.
export function normalizeEvent(raw) {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;

  if (raw.req && typeof raw.req === 'object') {
    const req = raw.req;
    return {
      ts: typeof raw.ts === 'number' ? raw.ts : null,
      host: req.host || '(unknown)',
      method: req.method || '',
      uri: req.uri || '',
      status: Number.isFinite(raw.status) ? raw.status : toInt(raw.status) || null,
      size: toInt(raw.size),
      ua: pickHeader(req.headers, 'User-Agent'),
      remote: req.remote_ip || '',
      format: 'caddy',
    };
  }

  const ua = raw.http_user_agent ?? raw.user_agent ?? raw.ua;
  if (ua === undefined && raw.request === undefined && raw.status === undefined) return null;

  let method = raw.method || '';
  let uri = raw.uri || raw.request_uri || '';
  if ((!method || !uri) && typeof raw.request === 'string') {
    const parts = raw.request.split(' ');
    if (parts.length >= 2) {
      method = method || parts[0];
      uri = uri || parts[1];
    }
  }

  return {
    ts: parseTs(raw),
    host: raw.server_name || raw.host || raw.hostname || '(unknown)',
    method,
    uri,
    status: toInt(raw.status) || null,
    size: toInt(raw.body_bytes_sent ?? raw.bytes_sent ?? raw.bytes),
    ua: typeof ua === 'string' ? ua : '',
    remote: raw.remote_addr || '',
    format: 'nginx',
  };
}

// Apache/NCSA "combined" format, still the default on many shared hosts.
const APACHE_RE =
  /^(\S+)\s+(\S+)\s+(\S+)\s+\[([^\]]+)\]\s+"([^"]*)"\s+(\d{3})\s+(\S+)(?:\s+"([^"]*)"\s+"([^"]*)")?/;

export function parseApacheLine(line) {
  const m = APACHE_RE.exec(line.trim());
  if (!m) return null;
  // In combined format the first field is the client address (there is no
  // vhost field), so it feeds `remote` for identity verification.
  const [, client, , , timeLocal, request, status, bytes, , ua] = m;
  const looksIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(client) || client.includes(':');
  let method = '';
  let uri = '';
  const rp = request.split(' ');
  if (rp.length >= 2) {
    method = rp[0];
    uri = rp[1];
  }
  return {
    ts: parseTs({ time_local: timeLocal }),
    host: looksIp ? '(unknown)' : client === '-' ? '(unknown)' : client,
    method,
    uri,
    status: Number(status),
    size: bytes === '-' ? 0 : Number(bytes) || 0,
    ua: ua || '',
    remote: looksIp ? client : '',
    format: 'apache',
  };
}

export function createStats() {
  return {
    files: 0,
    lines: 0,
    parsed: 0,
    unparsed: 0,
    filtered: 0,
    aiRequests: 0,
    aiBytes: 0,
    bots: new Map(),   // token -> per-bot aggregate
    unmatched: new Map(), // ua -> { requests, hosts:Set }
  };
}

function dayOf(ts) {
  return new Date(ts * 1000).toISOString().slice(0, 10);
}

function addBounded(map, key, cap) {
  if (map.has(key) || map.size < cap) {
    map.set(key, (map.get(key) ?? 0) + 1);
  }
}

function addIp(set, ip) {
  if (ip && (set.has(ip) || set.size < 50000)) set.add(ip);
}

// Merge version-suffixed UAs (Scrapy/2.11, Scrapy/2.12) into one bucket per
// product so the unmatched table isn't fragmented across releases.
function unmatchedKey(ua) {
  return ua.replace(/\/\d[\w.-]*/g, '/*');
}

export function ingestEvent(stats, ev, matchers) {
  const c = classifyUA(ev.ua, matchers);
  if (!c) {
    if (ev.ua && BOTLIKE.test(ev.ua)) {
      const key = unmatchedKey(ev.ua);
      let u = stats.unmatched.get(key);
      if (!u) {
        if (stats.unmatched.size >= MAX_UNMATCHED_UAS) return false;
        u = { display: ev.ua, requests: 0, hosts: new Set() };
        stats.unmatched.set(key, u);
      }
      u.requests++;
      if (ev.host) u.hosts.add(ev.host);
    }
    return false;
  }

  let b = stats.bots.get(c.token);
  if (!b) {
    b = {
      token: c.token,
      vendor: c.vendor,
      purpose: c.purpose ?? '',
      doc: c.doc ?? '',
      requests: 0,
      bytes: 0,
      hosts: new Set(),
      days: new Set(),
      hours: new Map(),
      ips: new Set(),
      statuses: new Map(),
      paths: new Map(),
      robots: 0,
    };
    stats.bots.set(c.token, b);
  }
  b.requests++;
  stats.aiRequests++;
  stats.aiBytes += ev.size;
  b.bytes += ev.size;
  if (ev.host) b.hosts.add(ev.host);
  if (ev.remote) addIp(b.ips, ev.remote);
  if (ev.ts) {
    b.days.add(dayOf(ev.ts));
    addBounded(b.hours, Math.floor(ev.ts / 3600), MAX_TRACKED_HOURS);
  }
  const st = ev.status ?? 'n/a';
  b.statuses.set(st, (b.statuses.get(st) ?? 0) + 1);
  if (ev.uri) addBounded(b.paths, ev.uri);
  if (ev.uri === '/robots.txt') b.robots++;
  return true;
}

// Sniff the gzip magic bytes instead of trusting the file extension —
// rotated logs get renamed, and misclassifying gzip as text turns every
// line into "unparsed".
function isGzipFile(path) {
  let fd;
  try {
    fd = openSync(path, 'r');
    const buf = Buffer.alloc(2);
    return readSync(fd, buf, 0, 2, 0) === 2 && buf[0] === 0x1f && buf[1] === 0x8b;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* already closed */ }
    }
  }
}

async function* jsonLines(path) {
  const input = createReadStream(path);
  const stream = isGzipFile(path) ? input.pipe(createGunzip()) : input;
  const rl = createInterface({ input: stream, crlfDelay: Infinity });
  for await (const line of rl) yield line;
}

export async function analyzeFiles(files, matchers, opts = {}) {
  const { stats = createStats(), since = null, until = null } = opts;
  const filtering = since !== null || until !== null;
  const failed = [];
  for (const f of files) {
    stats.files++;
    try {
      for await (const line of jsonLines(f)) {
        if (!line.trim()) continue;
        stats.lines++;
        let ev = null;
        try {
          ev = normalizeEvent(JSON.parse(line));
        } catch {
          ev = parseApacheLine(line);
        }
        if (!ev) {
          stats.unparsed++;
          continue;
        }
        if (filtering) {
          // An undated event can't be placed in the window; when the user
          // asks for a window we exclude it rather than guess.
          if (ev.ts === null || (since !== null && ev.ts < since) || (until !== null && ev.ts > until)) {
            stats.filtered++;
            continue;
          }
        }
        stats.parsed++;
        ingestEvent(stats, ev, matchers);
      }
    } catch (err) {
      failed.push({ file: f, error: err.message });
    }
  }
  return { stats, failed };
}

// ---- reporting ------------------------------------------------------------

function fmtInt(n) {
  return n.toLocaleString('en-US');
}

function fmtMB(bytes) {
  if (bytes < 1e6) return `${(bytes / 1e3).toFixed(0)} KB`;
  return `${(bytes / 1e6).toFixed(2)} MB`;
}

function pct(part, whole) {
  return whole > 0 ? `${((part / whole) * 100).toFixed(1)}%` : '—';
}

function truncate(s, n) {
  return s.length > n ? `${s.slice(0, n - 1)}…` : s;
}

function peakRate(hoursMap) {
  let best = 0;
  let bucket = null;
  for (const [h, n] of hoursMap) {
    if (n > best) {
      best = n;
      bucket = h;
    }
  }
  return { rph: best, hourTs: bucket === null ? null : bucket * 3600 };
}

export function buildReport(stats, { top = 15 } = {}) {
  const bots = [...stats.bots.values()].sort((a, b) => b.requests - a.requests);

  const vendors = new Map();
  for (const b of bots) {
    let v = vendors.get(b.vendor);
    if (!v) {
      v = { vendor: b.vendor, requests: 0, bytes: 0, tokens: [] };
      vendors.set(b.vendor, v);
    }
    v.requests += b.requests;
    v.bytes += b.bytes;
    v.tokens.push(b.token);
  }

  const statusTotals = new Map();
  const pathTotals = new Map();
  for (const b of bots) {
    for (const [s, n] of b.statuses) statusTotals.set(s, (statusTotals.get(s) ?? 0) + n);
    for (const [p, n] of b.paths) pathTotals.set(p, (pathTotals.get(p) ?? 0) + n);
  }

  return {
    meta: {
      tool: 'crawlward',
      version: VERSION,
      generated: new Date().toISOString(),
      files: stats.files,
      lines: stats.lines,
      parsed: stats.parsed,
      unparsed: stats.unparsed,
      filtered: stats.filtered,
      aiRequests: stats.aiRequests,
      aiBytes: stats.aiBytes,
      aiShare: stats.parsed > 0 ? stats.aiRequests / stats.parsed : 0,
    },
    byBot: bots.map((b) => {
      const peak = peakRate(b.hours);
      return {
        token: b.token,
        vendor: b.vendor,
        purpose: b.purpose,
        requests: b.requests,
        bytes: b.bytes,
        hosts: b.hosts.size,
        distinctIps: b.ips.size,
        days: b.days.size,
        peakRph: peak.rph,
        peakHour: peak.hourTs === null ? null : new Date(peak.hourTs * 1000).toISOString(),
        robotsTxtFetches: b.robots,
        statuses: Object.fromEntries([...b.statuses.entries()].sort()),
        topPaths: [...b.paths.entries()].sort((a, z) => z[1] - a[1]).slice(0, top).map(([path, count]) => ({ path, count })),
      };
    }),
    byVendor: [...vendors.values()].sort((a, b) => b.requests - a.requests),
    topPaths: [...pathTotals.entries()].sort((a, z) => z[1] - a[1]).slice(0, top).map(([path, count]) => ({ path, count })),
    statuses: Object.fromEntries([...statusTotals.entries()].sort()),
    robotsFetchers: bots.filter((b) => b.robots > 0).map((b) => ({ token: b.token, fetches: b.robots })),
    unmatchedBots: [...stats.unmatched.entries()]
      .sort((a, z) => z[1].requests - a[1].requests)
      .slice(0, top)
      .map(([, u]) => ({ ua: u.display, requests: u.requests, hosts: u.hosts.size })),
  };
}

export function renderReport(report, { top = 15 } = {}) {
  const { meta } = report;
  const out = [];
  out.push(`# crawlward v${VERSION} — who really crawls`);
  out.push(
    `files: ${meta.files} · lines: ${fmtInt(meta.lines)} · parsed: ${fmtInt(meta.parsed)} · unparsed: ${fmtInt(meta.unparsed)}`,
  );
  out.push(
    `AI-crawler requests: ${fmtInt(meta.aiRequests)} (${pct(meta.aiRequests, meta.parsed)} of parsed) · ${fmtMB(meta.aiBytes)} served\n`,
  );

  if (report.byBot.length === 0) {
    out.push('(no AI crawler traffic found — that is a finding too, given registry coverage)');
    return out.join('\n');
  }

  out.push('## AI crawler requests, by bot');
  out.push('requests  share  served   days  peak/h  bot · vendor — purpose');
  for (const b of report.byBot.slice(0, top)) {
    out.push(
      `${fmtInt(b.requests).padStart(8)}  ${pct(b.requests, meta.aiRequests).padStart(6)}  ${fmtMB(b.bytes).padStart(7)}  ${String(b.days).padStart(4)}  ${String(b.peakRph).padStart(6)}  ${b.token} · ${b.vendor} — ${b.purpose}`,
    );
  }

  out.push('\n## By vendor');
  for (const v of report.byVendor.slice(0, top)) {
    out.push(`${fmtInt(v.requests).padStart(8)}  ${fmtMB(v.bytes).padStart(7)}  ${v.vendor} (${v.tokens.join(', ')})`);
  }

  if (report.topPaths.length > 0) {
    out.push('\n## What AI crawlers want most (top paths)');
    for (const p of report.topPaths) {
      out.push(`${fmtInt(p.count).padStart(8)}  ${truncate(p.path, 90)}`);
    }
  }

  const statusParts = Object.entries(report.statuses).map(([s, n]) => `${s}: ${fmtInt(n)}`);
  out.push(`\n## HTTP status of AI crawler requests`);
  out.push(statusParts.join(' · '));
  const err = Object.entries(report.statuses)
    .filter(([s]) => s.startsWith('4') || s.startsWith('5'))
    .reduce((acc, [, n]) => acc + n, 0);
  if (err > 0) out.push(`(error responses: ${fmtInt(err)} — 404/410/403 waves often mean probing or stale caches)`);

  if (report.robotsFetchers.length > 0) {
    out.push('\n## robots.txt awareness');
    for (const r of report.robotsFetchers) {
      out.push(`${r.token} requested /robots.txt ${fmtInt(r.fetches)}×`);
    }
    const noRobots = report.byBot.filter((b) => b.robotsTxtFetches === 0).map((b) => b.token);
    if (noRobots.length > 0) out.push(`no /robots.txt request seen from: ${noRobots.join(', ')} (weak signal — crawlers may cache it)`);
  }

  if (report.unmatchedBots.length > 0) {
    out.push('\n## Bot-like user agents NOT in the registry');
    for (const u of report.unmatchedBots) {
      out.push(`${fmtInt(u.requests).padStart(8)}  ${truncate(u.ua, 100)}`);
    }
    out.push('(candidates for the registry — verify identity before adding)');
  }

  if (report.verification && report.verification.length > 0) {
    out.push('\n## Identity verification (--verify: claimed identity vs vendor IP ranges)');
    for (const v of report.verification) {
      if (v.status === 'no-ranges') {
        out.push(`${v.token.padEnd(22)} vendor publishes no IP ranges — cannot verify`);
      } else if (v.status === 'unavailable') {
        out.push(`${v.token.padEnd(22)} ranges unavailable (${v.error})`);
      } else if (v.uniqueIps === 0) {
        out.push(`${v.token.padEnd(22)} no source IPs in these logs — cannot verify (log remote_addr / remote_ip)`);
      } else if (v.share === 1) {
        out.push(`${v.token.padEnd(22)} all ${fmtInt(v.uniqueIps)} source IP(s) inside vendor ranges (${v.prefixes} prefixes) — identity consistent`);
      } else if (v.share === 0) {
        out.push(`${v.token.padEnd(22)} ${fmtInt(v.uniqueIps)}/${fmtInt(v.uniqueIps)} source IP(s) OUTSIDE vendor ranges (${v.prefixes} prefixes) — treat claimed identity as spoofed`);
      } else {
        out.push(`${v.token.padEnd(22)} ${fmtInt(v.outside)}/${fmtInt(v.uniqueIps)} source IP(s) outside vendor ranges (${v.prefixes} prefixes) — MIXED identity, inspect closely`);
      }
      if (v.status === 'checked' && v.share < 1 && v.outsideSample.length > 0) {
        out.push(`${' '.repeat(23)}outside IP sample: ${v.outsideSample.join(', ')}`);
      }
    }
  }

  return out.join('\n');
}

function csvEscape(v) {
  const s = String(v ?? '');
  return /[",\n]/.test(s) ? `"${s.replaceAll('"', '""')}"` : s;
}

export function renderCsv(report) {
  const head = 'token,vendor,purpose,requests,bytes,hosts,distinctIps,days,peakRph,robotsTxtFetches';
  const rows = report.byBot.map((b) =>
    [b.token, b.vendor, b.purpose, b.requests, b.bytes, b.hosts, b.distinctIps, b.days, b.peakRph, b.robotsTxtFetches]
      .map(csvEscape)
      .join(','),
  );
  return [head, ...rows].join('\n');
}

// ---- CLI ------------------------------------------------------------------

function printHelp() {
  console.log(`crawlward v${VERSION} — watchdog for AI crawlers at your own origin

Usage:
  crawlward [options] <access.log> [<more.log> ...]

Options:
  --verify        check claimed bot identities against vendors' published IP
                  ranges (fetches a few small JSON files; needs network)
  --json          emit a machine-readable JSON report instead of tables
  --csv           emit the per-bot table as CSV (overrides --json)
  --since <date>  only events on/after this date (YYYY-MM-DD is read as
                  UTC midnight; full ISO 8601 also works)
  --until <date>  only events up to this date (same format as --since).
                  Events without a timestamp are excluded while filtering.
  --top <n>       rows per table (default: 15)
  -h, --help      show this help
  -V, --version   show version

Input: JSONL access logs from Caddy (log { format json }), nginx
(log_format ... escape=json), or Apache combined format. gzip is detected
by content, so compressed rotations work under any filename.
Zero dependencies.`);
}

// Accepts YYYY-MM-DD (UTC day start), full ISO 8601, or epoch seconds.
function parseWhen(s) {
  if (/^\d{9,13}$/.test(s)) return epochSeconds(Number(s));
  const d = Date.parse(/^\d{4}-\d{2}-\d{2}$/.test(s) ? `${s}T00:00:00Z` : s);
  return Number.isNaN(d) ? null : d / 1000;
}

async function main() {
  const argv = process.argv.slice(2);
  let json = false;
  let csv = false;
  let verify = false;
  let top = 15;
  let since = null;
  let until = null;
  const files = [];

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--json') json = true;
    else if (a === '--csv') csv = true;
    else if (a === '--verify') verify = true;
    else if (a === '--since') since = parseWhen(argv[++i] ?? '');
    else if (a.startsWith('--since=')) since = parseWhen(a.slice(7));
    else if (a === '--until') until = parseWhen(argv[++i] ?? '');
    else if (a.startsWith('--until=')) until = parseWhen(a.slice(7));
    else if (a === '--top') top = Number(argv[++i]) || 15;
    else if (a.startsWith('--top=')) top = Number(a.slice(6)) || 15;
    else if (a === '-h' || a === '--help') { printHelp(); return; }
    else if (a === '-V' || a === '--version') { console.log(VERSION); return; }
    else files.push(a);
  }

  const askedSince = argv.some((a) => a === '--since' || a.startsWith('--since='));
  const askedUntil = argv.some((a) => a === '--until' || a.startsWith('--until='));
  if ((askedSince && since === null) || (askedUntil && until === null)) {
    console.error('crawlward: could not parse --since/--until date');
    process.exit(1);
  }
  if (files.length === 0) {
    printHelp();
    process.exit(1);
  }

  const matchers = compileMatchers(loadRegistry());
  const { stats, failed } = await analyzeFiles(files, matchers, { since, until });
  const report = buildReport(stats, { top });

  if (verify) {
    const entries = [...stats.bots.values()]
      .map((b) => {
        const reg = matchers.find((m) => m.token === b.token);
        return { token: b.token, ranges: reg?.ranges, ips: [...b.ips] };
      });
    report.verification = await verifyBots(entries);
  }

  for (const f of failed) console.error(`crawlward: cannot read ${f.file}: ${f.error}`);
  const out = csv ? renderCsv(report) : json ? JSON.stringify(report, null, 2) : renderReport(report, { top });
  console.log(out);
  if (failed.length > 0) process.exit(2);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
