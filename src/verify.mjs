// crawlward identity verification — check that requests claiming a vendor's
// bot identity actually come from that vendor's published IP prefixes.
// Zero dependencies: prefix lists are fetched with global fetch (Node >= 18).

// ---- IP / CIDR math -------------------------------------------------------

function ipv4ToBigInt(ip) {
  const parts = ip.split('.');
  if (parts.length !== 4) return null;
  let n = 0n;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v > 255) return null;
    n = (n << 8n) | BigInt(v);
  }
  return n;
}

// Splits an IPv6 string into 8 hextet groups. Handles `::` compression and
// dotted-quad tails (::ffff:1.2.3.4, 64:ff9b::192.0.2.33, full form
// 1:2:3:4:5:6:1.2.3.4). Returns null on anything invalid.
function ipv6ToGroups(ip) {
  const z = ip.indexOf('%'); // strip zone index (::1%eth0)
  const s = z === -1 ? ip : ip.slice(0, z);
  if (s.split('::').length > 2) return null; // only one `::` allowed

  const dc = s.indexOf('::');
  const head = dc === -1 ? s : s.slice(0, dc);
  const tail = dc === -1 ? '' : s.slice(dc + 2);

  const parsePiece = (piece) => {
    if (piece === '') return [];
    const out = [];
    const parts = piece.split(':');
    for (let i = 0; i < parts.length; i++) {
      const g = parts[i];
      if (g.includes('.')) {
        // dotted quad is only valid as the last group of a piece
        if (i !== parts.length - 1) return null;
        const v4 = ipv4ToBigInt(g);
        if (v4 === null) return null;
        out.push((v4 >> 16n) & 0xffffn, v4 & 0xffffn);
      } else if (/^[0-9a-fA-F]{1,4}$/.test(g)) {
        out.push(BigInt(parseInt(g, 16)));
      } else {
        return null;
      }
    }
    return out;
  };

  const h = parsePiece(head);
  if (h === null) return null;
  const t = parsePiece(tail);
  if (t === null) return null;

  if (dc === -1) {
    if (h.length !== 8) return null;
    return h;
  }
  if (h.length + t.length > 7) return null;
  const fill = 8 - h.length - t.length;
  return [...h, ...Array(fill).fill(0n), ...t];
}

// Parses an IPv4 or IPv6 address into { value: BigInt, family: 4|6 }.
// IPv4-mapped IPv6 (::ffff:0:0/96 — how nginx dual-stack logs IPv4 clients)
// canonicalizes onto the embedded IPv4 so vendor v4 ranges match.
export function parseIp(ip) {
  if (typeof ip !== 'string' || !ip) return null;
  if (!ip.includes(':')) {
    const v = ipv4ToBigInt(ip);
    return v === null ? null : { value: v, family: 4 };
  }
  const groups = ipv6ToGroups(ip);
  if (groups === null) return null;
  const isMapped =
    groups.slice(0, 5).every((g) => g === 0n) && groups[5] === 0xffffn;
  if (isMapped) {
    return { value: (groups[6] << 16n) | groups[7], family: 4 };
  }
  let n = 0n;
  for (const g of groups) n = (n << 16n) | g;
  return { value: n, family: 6 };
}

// Legacy helper kept for API stability: returns just the numeric value.
export function ipToBigInt(ip) {
  const p = parseIp(ip);
  return p === null ? null : p.value;
}

export function parseCidr(cidr) {
  if (typeof cidr !== 'string') return null;
  const slash = cidr.indexOf('/');
  const addr = slash === -1 ? cidr : cidr.slice(0, slash);
  const bits = slash === -1 ? null : Number(cidr.slice(slash + 1));
  const ip = ipToBigInt(addr);
  if (ip === null) return null;
  const maxBits = addr.includes(':') ? 128 : 32;
  if (bits === null) return { ip, bits: maxBits, family: maxBits === 32 ? 4 : 6 };
  if (!Number.isInteger(bits) || bits < 0 || bits > maxBits) return null;
  return { ip, bits, family: maxBits === 32 ? 4 : 6 };
}

// A prefix list entry is a /block; an IP belongs if its top `bits` match.
export function ipInCidr(ipBig, cidr) {
  const p = parseCidr(cidr);
  if (!p || ipBig === null) return false;
  return sameNetwork(ipBig, p);
}

function sameNetwork(ipBig, prefix) {
  const shift = BigInt(prefix.family === 4 ? 32 : 128) - BigInt(prefix.bits);
  return ipBig >> shift === prefix.ip >> shift;
}

export function buildRangeSet(prefixes) {
  const v4 = [];
  const v6 = [];
  for (const p of prefixes) {
    const parsed = parseCidr(p);
    if (!parsed) continue;
    (parsed.family === 4 ? v4 : v6).push(parsed);
  }
  return { v4, v6 };
}

// Accepts a string address (preferred — family-aware, canonicalizes
// v4-mapped IPv6), a parseIp() result, or a legacy bare BigInt (family
// unknown in that form, so both tables are tried).
export function ipInSet(ip, set) {
  if (!set) return false;
  let value;
  let family;
  if (typeof ip === 'string') {
    const p = parseIp(ip);
    if (!p) return false;
    ({ value, family } = p);
  } else if (ip && typeof ip === 'object' && typeof ip.value === 'bigint') {
    ({ value, family } = ip);
  } else if (typeof ip === 'bigint') {
    for (const p of set.v4) if (sameNetwork(ip, p)) return true;
    for (const p of set.v6) if (sameNetwork(ip, p)) return true;
    return false;
  } else {
    return false;
  }
  const table = family === 4 ? set.v4 : set.v6;
  for (const p of table) if (sameNetwork(value, p)) return true;
  return false;
}

// ---- prefix-list ingestion ------------------------------------------------

// Vendor files share the Google-style shape
// { creationTime, prefixes: [{ipv4Prefix|ipv6Prefix}] } — but walk the whole
// object defensively so small format drift doesn't break verification.
export function extractPrefixes(json) {
  const out = [];
  const walk = (node) => {
    if (Array.isArray(node)) {
      for (const n of node) walk(n);
    } else if (node && typeof node === 'object') {
      for (const [k, v] of Object.entries(node)) {
        if ((k === 'ipv4Prefix' || k === 'ipv6Prefix' || k === 'ip_prefix' || k === 'ipv6_prefix') && typeof v === 'string') {
          out.push(v);
        } else {
          walk(v);
        }
      }
    }
  };
  walk(json);
  return out;
}

export async function fetchPrefixList(url, fetchImpl = fetch, timeoutMs = 8000) {
  const res = await fetchImpl(url, { signal: AbortSignal.timeout(timeoutMs) });
  if (!res.ok) throw new Error(`HTTP ${res.status} from ${url}`);
  return extractPrefixes(await res.json());
}

// ---- verification ---------------------------------------------------------

// For each bot entry ({token, ranges}), fetch its prefix list once and count
// how many of the bot's requests (ips: string[]) fall inside vendor ranges.
// `fetchImpl` is injectable for tests/offline use.
export async function verifyBots(entries, fetchImpl = fetch) {
  const cache = new Map(); // url -> Promise<{prefixes, error}>
  const load = (url) => {
    if (!cache.has(url)) {
      cache.set(
        url,
        fetchPrefixList(url, fetchImpl)
          .then((prefixes) => ({ prefixes, error: null }))
          .catch((err) => ({ prefixes: [], error: err.message })),
      );
    }
    return cache.get(url);
  };

  const results = [];
  for (const e of entries) {
    if (!e.ranges) {
      results.push({ token: e.token, rangesUrl: null, status: 'no-ranges' });
      continue;
    }
    const { prefixes, error } = await load(e.ranges);
    if (error) {
      results.push({ token: e.token, rangesUrl: e.ranges, status: 'unavailable', error });
      continue;
    }
    const set = buildRangeSet(prefixes);
    let inside = 0;
    const outsideIps = new Set();
    for (const ip of e.ips) {
      if (ipInSet(ip, set)) inside++;
      else outsideIps.add(ip);
    }
    results.push({
      token: e.token,
      rangesUrl: e.ranges,
      status: 'checked',
      prefixes: prefixes.length,
      uniqueIps: e.ips.length,
      fromVendorRanges: inside,
      outside: e.ips.length - inside,
      share: e.ips.length > 0 ? inside / e.ips.length : null,
      outsideSample: [...outsideIps].slice(0, 5),
    });
  }
  return results;
}
