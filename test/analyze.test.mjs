import { test } from 'node:test';
import assert from 'node:assert/strict';
import { gzipSync } from 'node:zlib';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  loadRegistry,
  compileMatchers,
  classifyUA,
  normalizeEvent,
  parseApacheLine,
  createStats,
  ingestEvent,
  analyzeFiles,
  buildReport,
  renderReport,
  renderCsv,
} from '../src/analyze.mjs';

const registry = loadRegistry();
const matchers = compileMatchers(registry);

const caddyFixture = readFileSync(new URL('./fixtures/caddy-sample.log', import.meta.url), 'utf8');
const nginxFixture = readFileSync(new URL('./fixtures/nginx-sample.log', import.meta.url), 'utf8');
const apacheFixture = readFileSync(new URL('./fixtures/apache-sample.log', import.meta.url), 'utf8');

function ingestFixtures(stats) {
  for (const line of [...caddyFixture.split('\n'), ...nginxFixture.split('\n')]) {
    if (!line.trim()) continue;
    stats.lines++;
    let ev = null;
    try {
      ev = normalizeEvent(JSON.parse(line));
    } catch {
      stats.unparsed++;
      continue;
    }
    if (ev) {
      stats.parsed++;
      ingestEvent(stats, ev, matchers);
    }
  }
  return stats;
}

test('registry loads and every entry has the required fields', () => {
  assert.ok(registry.length >= 20, 'registry should keep a healthy size');
  for (const c of registry) {
    assert.equal(typeof c.token, 'string', 'token must be a string');
    assert.ok(c.token.length > 0);
    assert.equal(typeof c.vendor, 'string');
    assert.equal(typeof c.purpose, 'string');
  }
});

test('classifyUA matches tokens regardless of UA casing around them', () => {
  const hit = classifyUA('Mozilla/5.0 (compatible; GPTBot/1.2; +https://openai.com/gptbot)', matchers);
  assert.equal(hit.token, 'GPTBot');
  assert.equal(hit.vendor, 'OpenAI');
  assert.equal(classifyUA('Mozilla/5.0 (Macintosh) Chrome/126.0 Safari/537.36', matchers), null);
  assert.equal(classifyUA('', matchers), null);
});

test('matching is case-insensitive (Meta wire UAs are lowercase)', () => {
  const lower = classifyUA('meta-externalagent/1.1 (+https://developers.facebook.com/docs/sharing/webmasters/crawler)', matchers);
  assert.equal(lower.token, 'meta-externalagent');
  const upper = classifyUA('Mozilla/5.0 (compatible; Meta-ExternalAgent/1.1)', matchers);
  assert.equal(upper.token, 'meta-externalagent');
});

test('longer tokens win over shorter prefixes', () => {
  const googleOtherImage = { token: 'GoogleOther-Image', vendor: 'Google', purpose: 'x' };
  const googleOther = { token: 'GoogleOther', vendor: 'Google', purpose: 'x' };
  const m = compileMatchers([googleOther, googleOtherImage]);
  assert.equal(classifyUA('Mozilla/5.0 (compatible; GoogleOther-Image/1.0)', m).token, 'GoogleOther-Image');
});

test('normalizeEvent understands the Caddy JSON shape', () => {
  const raw = JSON.parse(caddyFixture.split('\n')[1]);
  const ev = normalizeEvent(raw);
  assert.equal(ev.host, 'example.com');
  assert.equal(ev.uri, '/robots.txt');
  assert.equal(ev.status, 200);
  assert.equal(ev.size, 312);
  assert.ok(ev.ua.includes('GPTBot'));
  assert.ok(ev.ts > 1e9);
});

test('normalizeEvent understands common nginx JSON shapes', () => {
  const raw = JSON.parse(nginxFixture.split('\n')[0]);
  const ev = normalizeEvent(raw);
  assert.equal(ev.host, 'example.net');
  assert.equal(ev.method, 'GET');
  assert.equal(ev.uri, '/');
  assert.equal(ev.status, 200);
  assert.equal(ev.size, 2048);
  assert.ok(ev.ua.includes('OAI-SearchBot'));
  assert.equal(new Date(ev.ts * 1000).toISOString().slice(0, 10), '2026-09-07');
});

test('normalizeEvent rejects junk', () => {
  assert.equal(normalizeEvent(null), null);
  assert.equal(normalizeEvent('nope'), null);
  assert.equal(normalizeEvent([1, 2]), null);
});

test('ingestEvent aggregates requests, bytes, days and robots.txt fetches', () => {
  const stats = ingestFixtures(createStats());
  // GPTBot x3 (one on a second day, incl. /robots.txt), ClaudeBot x1,
  // Bytespider x1, PerplexityBot x1, OAI-SearchBot x2
  assert.equal(stats.aiRequests, 8);
  assert.equal(stats.lines, 11);
  assert.equal(stats.parsed, 10);
  assert.equal(stats.unparsed, 1);

  const gpt = stats.bots.get('GPTBot');
  assert.equal(gpt.requests, 3);
  assert.equal(gpt.robots, 1);
  assert.equal(gpt.days.size, 2);
  assert.equal(gpt.hosts.size, 1);

  const claude = stats.bots.get('ClaudeBot');
  assert.equal(claude.statuses.get(404), 1);
});

test('non-registry bot-like UAs land in the unmatched bucket', () => {
  const stats = ingestFixtures(createStats());
  const scrapy = [...stats.unmatched.values()].find((u) => u.display.startsWith('Scrapy'));
  assert.ok(scrapy, 'Scrapy should be flagged as bot-like');
  assert.equal(scrapy.requests, 1);
  assert.equal(scrapy.hosts.size, 1);
  const noBrowser = [...stats.unmatched.values()].find((u) => u.display.includes('Chrome/126'));
  assert.equal(noBrowser, undefined); // plain browser UAs are not flagged
});

test('analyzeFiles reads plain and gzip JSONL, tolerating bad lines', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'crawlward-test-'));
  const plain = join(dir, 'a.log');
  const gz = join(dir, 'b.log.gz');
  writeFileSync(plain, caddyFixture);
  writeFileSync(gz, gzipSync(nginxFixture));

  const { stats, failed } = await analyzeFiles([plain, gz], matchers);
  assert.deepEqual(failed, []);
  assert.equal(stats.files, 2);
  assert.equal(stats.lines, 11);
  assert.equal(stats.aiRequests, 8);
});

test('analyzeFiles reports unreadable files instead of crashing', async () => {
  const { stats, failed } = await analyzeFiles(['/nonexistent/path/x.log'], matchers);
  assert.equal(stats.lines, 0);
  assert.equal(failed.length, 1);
  assert.match(failed[0].error, /ENOENT|no such file|cannot/i);
});

test('buildReport produces a serializable summary', () => {
  const report = buildReport(ingestFixtures(createStats()));
  const serialized = JSON.stringify(report); // must not throw
  assert.ok(serialized.includes('GPTBot'));
  assert.equal(report.meta.aiRequests, 8);
  assert.ok(report.byBot[0].requests >= report.byBot[report.byBot.length - 1].requests);
  assert.equal(report.statuses[404], 1);
  assert.equal(report.byVendor.find((v) => v.vendor === 'OpenAI').requests, 5);
});

test('renderReport includes the sections that matter', () => {
  const text = renderReport(buildReport(ingestFixtures(createStats())));
  assert.match(text, /# crawlward/);
  assert.match(text, /GPTBot/);
  assert.match(text, /robots\.txt awareness/);
  assert.match(text, /NOT in the registry/);
  assert.match(text, /Scrapy/);
});

test('renderReport handles a log with zero AI traffic', () => {
  const stats = createStats();
  stats.lines = 5;
  stats.parsed = 5;
  const text = renderReport(buildReport(stats));
  assert.match(text, /no AI crawler traffic found/);
});

test('parseApacheLine understands combined format', () => {
  const line = apacheFixture.split('\n')[0];
  const ev = parseApacheLine(line);
  assert.equal(ev.remote, '198.51.100.20'); // client IP feeds verification
  assert.equal(ev.host, '(unknown)'); // combined format has no vhost field
  assert.equal(ev.uri, '/');
  assert.equal(ev.status, 200);
  assert.equal(ev.size, 5120);
  assert.ok(ev.ua.includes('CCBot'));
  assert.equal(new Date(ev.ts * 1000).toISOString().slice(0, 10), '2026-09-07');
  assert.equal(parseApacheLine('not an apache line'), null);
});

test('analyzeFiles auto-detects Apache combined logs alongside JSON', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'crawlward-test-'));
  const apache = join(dir, 'c.access.log');
  writeFileSync(apache, apacheFixture);
  const { stats } = await analyzeFiles([apache], matchers);
  // 2 CCBot lines + 1 DataForSeoBot (unmatched, bot-like)
  assert.equal(stats.parsed, 3);
  assert.equal(stats.aiRequests, 2);
  assert.ok([...stats.unmatched.values()].some((u) => u.display.startsWith('DataForSeoBot')));
});

test('peak request rate is computed per bot', () => {
  const stats = createStats();
  // 3 GPTBot requests within the same hour, one in the next hour
  const hour = 1788739200; // 2026-09-07T00:00Z, epoch seconds
  for (let i = 0; i < 3; i++) {
    ingestEvent(stats, { ts: hour + i * 60, host: 'h', uri: '/x', status: 200, size: 10, ua: 'Mozilla/5.0 (compatible; GPTBot/1.2)', remote: '203.0.113.5' }, matchers);
  }
  ingestEvent(stats, { ts: hour + 7200, host: 'h', uri: '/y', status: 200, size: 10, ua: 'Mozilla/5.0 (compatible; GPTBot/1.2)', remote: '203.0.113.5' }, matchers);
  const report = buildReport(stats);
  const gpt = report.byBot[0];
  assert.equal(gpt.requests, 4);
  assert.equal(gpt.peakRph, 3);
  assert.equal(gpt.distinctIps, 1);
});

test('--since/--until filters drop out-of-window events', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'crawlward-test-'));
  const f = join(dir, 'w.log');
  // Fixture spans 2026-09-07 and 2026-09-08 (GPTBot second-post line).
  writeFileSync(f, caddyFixture);
  const since = Date.parse('2026-09-08T00:00:00Z') / 1000;
  const { stats } = await analyzeFiles([f], matchers, { since });
  assert.equal(stats.aiRequests, 1); // only the GPTBot 2026-09-08 request
  assert.equal(stats.filtered, 7); // the other 7 parsed events are before the window
});

test('renderCsv emits a header plus one row per bot', () => {
  const csv = renderCsv(buildReport(ingestFixtures(createStats())));
  const lines = csv.split('\n');
  assert.ok(lines[0].startsWith('token,vendor,purpose,requests'));
  assert.equal(lines.length, 6); // header + 5 bots
  assert.ok(lines.some((l) => l.startsWith('GPTBot,')));
});

test('undated events are excluded when --since/--until is active', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'crawlward-test-'));
  const f = join(dir, 'n.log');
  const noTs = JSON.stringify({ req: { host: 'x', uri: '/', headers: { 'User-Agent': ['GPTBot'] } }, status: 200, size: 1 });
  const dated = JSON.stringify({ ts: 1788739200, req: { host: 'x', uri: '/', headers: { 'User-Agent': ['GPTBot'] } }, status: 200, size: 1 });
  writeFileSync(f, `${noTs}\n${dated}\n`);

  const unfiltered = await analyzeFiles([f], matchers);
  assert.equal(unfiltered.stats.aiRequests, 2); // undated counted when not filtering

  const since = 1788739000;
  const { stats } = await analyzeFiles([f], matchers, { since });
  assert.equal(stats.aiRequests, 1); // only the dated event is provably in-window
  assert.equal(stats.filtered, 1);
});

test('gzip content is detected by magic bytes, not file extension', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'crawlward-test-'));
  const disguised = join(dir, 'rotated-access.log'); // gzip bytes, .log name
  writeFileSync(disguised, gzipSync(nginxFixture));
  const { stats, failed } = await analyzeFiles([disguised], matchers);
  assert.deepEqual(failed, []);
  assert.equal(stats.aiRequests, 2); // both OAI-SearchBot lines parsed
  assert.equal(stats.unparsed, 0);
});

test('unmatched bot-like UAs are version-normalized into one bucket', () => {
  const stats = createStats();
  const base = { host: 'h', uri: '/', status: 200, size: 1, remote: '' };
  ingestEvent(stats, { ...base, ua: 'Scrapy/2.11 (+https://scrapy.org)' }, matchers);
  ingestEvent(stats, { ...base, ua: 'Scrapy/2.12.1 (+https://scrapy.org)' }, matchers);
  ingestEvent(stats, { ...base, ua: 'DataForSeoBot/1.0' }, matchers);
  assert.equal(stats.unmatched.size, 2);
  const scrapy = [...stats.unmatched.values()].find((u) => u.display.startsWith('Scrapy'));
  assert.equal(scrapy.requests, 2);
});

test('peak hour beyond the first 5000 buckets is still counted', () => {
  const stats = createStats();
  const base = 1788739200; // epoch seconds
  const ua = 'Mozilla/5.0 (compatible; GPTBot/1.2)';
  // 1 request per hour for 6000 hours…
  for (let h = 0; h < 6000; h++) {
    ingestEvent(stats, { ts: base + h * 3600, host: 'h', uri: '/x', status: 200, size: 1, ua, remote: '' }, matchers);
  }
  // …then two requests inside hour #6001 (beyond the old 5000-bucket cap)
  ingestEvent(stats, { ts: base + 6001 * 3600, host: 'h', uri: '/x', status: 200, size: 1, ua, remote: '' }, matchers);
  ingestEvent(stats, { ts: base + 6001 * 3600 + 60, host: 'h', uri: '/x', status: 200, size: 1, ua, remote: '' }, matchers);
  const report = buildReport(stats);
  assert.equal(report.byBot[0].peakRph, 2);
  assert.equal(report.byBot[0].requests, 6002);
});

test('verification with zero source IPs renders an explicit cannot-verify', async () => {
  const { verifyBots } = await import('../src/verify.mjs');
  const fakeFetch = async () => ({ ok: true, json: async () => ({ prefixes: [{ ipv4Prefix: '1.2.3.0/24' }] }) });
  const stats = createStats();
  ingestEvent(stats, { ts: 1788739200, host: 'x', uri: '/', status: 200, size: 1, ua: 'GPTBot', remote: '' }, matchers);
  const report = buildReport(stats);
  report.verification = await verifyBots([{ token: 'GPTBot', ranges: 'https://x.json', ips: [...stats.bots.get('GPTBot').ips] }], fakeFetch);
  const text = renderReport(report);
  assert.match(text, /no source IPs in these logs — cannot verify/);
  assert.doesNotMatch(text, /MIXED identity/);
});
