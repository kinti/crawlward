// crawlward identity verification — check that requests claiming a vendor's
// bot identity actually come from that vendor's published IP prefixes.
// Zero dependencies: prefix lists are fetched with global fetch (Node >= 18).

// ---- IP / CIDR math -------------------------------------------------------

// Parse an IPv4 or IPv6 address into a BigInt. Returns null on invalid input.
export function ipToBigInt(ip) {
  if (typeof ip !== 'string' || !ip) return null;
  if (ip.includes(':')) return ipv6ToBigInt(ip);
  return ipv4ToBigInt(ip);
}

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

function ipv6ToBigInt(ip) {
  // Handles canonical compressed form ("2600:1f28:365:8000::/56" addresses).
  // IPv4-embedded endings (::ffff:1.2.3.4) are accepted.
  let head = ip;
  let tail = '';
  const dc = ip.indexOf('::');
  if (dc !== -1) {
    head = ip.slice(0, dc);
    tail = ip.slice(dc + 2);
  }
  const hextetsToBigInt = (s) => {
    if (s === '') return [];
    const out = [];
    for (const g of s.split(':')) {
      if (!/^[0-9a-fA-F]{1,4}$/.test(g)) return null;
      out.push(BigInt(parseInt(g, 16)));
    }
    return out;
  };
  let groups = hextetsToBigInt(head);
  if (groups === null) return null;
  const tailGroups = hextetsToBigInt(tail);
  if (tailGroups === null) return null;

  if (dc === -1) {
    if (groups.length !== 8) return null;
  } else {
    // An IPv4-embedded tail is written as one group per hextet already, or
    // as dotted quad — normalize the dotted case first.
    if (tail.includes('.')) {
      const v4 = ipv4ToBigInt(tail);
      if (v4 === null) return null;
      const hi = (v4 >> 16n) & 0xffffn;
      const lo = v4 & 0xffffn;
      const replaced = tail === '' ? [] : [hi, lo];
      tailGroups.splice(0, tailGroups.length, ...replaced);
    }
    if (groups.length + tailGroups.length > 7) return null;
    const fill = 8 - (groups.length + tailGroups.length);
    groups = [...groups, ...Array(fill).fill(0n), ...tailGroups];
  }

  // Last group may still be a dotted quad in full form, e.g. 1:2:3:4:5:6:1.2.3.4
  if (groups.length === 6 && ip.includes('.') && dc === -1) {
    const last = ip.split(':').pop();
    const v4 = ipv4ToBigInt(last);
    if (v4 === null) return null;
    groups = groups.slice(0, 5).concat([(v4 >> 16n) & 0xffffn, v4 & 0xffffn]);
  }

  let n = 0n;
  for (const g of groups) n = (n << 16n) | g;
  return n;
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

export function ipInSet(ipBig, set) {
  if (ipBig === null || !set) return false;
  const table = set.v4; // pick family by magnitude is wrong for v4-mapped; try both
  for (const p of table) if (sameNetwork(ipBig, p)) return true;
  for (const p of set.v6) if (sameNetwork(ipBig, p)) return true;
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
      if (ipInSet(ipToBigInt(ip), set)) inside++;
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
