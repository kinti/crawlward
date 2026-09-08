import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  ipToBigInt,
  parseCidr,
  ipInCidr,
  buildRangeSet,
  ipInSet,
  extractPrefixes,
  verifyBots,
} from '../src/verify.mjs';

test('ipToBigInt parses IPv4 and IPv6', () => {
  assert.equal(ipToBigInt('1.2.3.4'), BigInt('0x01020304'));
  assert.equal(ipToBigInt('255.255.255.255'), 2n ** 32n - 1n);
  assert.equal(ipToBigInt('::1'), 1n);
  assert.equal(ipToBigInt('2600:1f28:365:8000::'), BigInt('0x26001f28036580000000000000000000'));
  assert.equal(ipToBigInt('not-an-ip'), null);
  assert.equal(ipToBigInt('999.1.1.1'), null);
  assert.equal(ipToBigInt(''), null);
});

test('parseCidr handles bare addresses and invalid bits', () => {
  assert.equal(parseCidr('10.0.0.0/8').bits, 8);
  assert.equal(parseCidr('10.0.0.1').bits, 32);
  assert.equal(parseCidr('2600:1f28:365:8000::/56').bits, 56);
  assert.equal(parseCidr('10.0.0.0/33'), null);
  assert.equal(parseCidr('nope/8'), null);
});

test('ipInCidr matches IPv4 ranges', () => {
  assert.equal(ipInCidr(ipToBigInt('10.1.2.3'), '10.0.0.0/8'), true);
  assert.equal(ipInCidr(ipToBigInt('11.1.2.3'), '10.0.0.0/8'), false);
  assert.equal(ipInCidr(ipToBigInt('132.196.86.200'), '132.196.86.0/24'), true);
  assert.equal(ipInCidr(ipToBigInt('132.196.87.200'), '132.196.86.0/24'), false);
});

test('IPv6 ranges match correctly across compression', () => {
  const cidr = '2600:1f28:365:8000::/56';
  assert.equal(ipInCidr(ipToBigInt('2600:1f28:365:8000:1234::1'), cidr), true);
  assert.equal(ipInCidr(ipToBigInt('2600:1f28:365:8100::1'), cidr), false);
});

test('buildRangeSet + ipInSet route v4 and v6', () => {
  const set = buildRangeSet(['3.41.188.32/29', '2600:1f28:365:8000::/56']);
  assert.equal(ipInSet(ipToBigInt('3.41.188.35'), set), true);
  assert.equal(ipInSet(ipToBigInt('3.41.188.40'), set), false);
  assert.equal(ipInSet(ipToBigInt('2600:1f28:365:8000::abcd'), set), true);
  assert.equal(ipInSet(null, set), false);
});

test('extractPrefixes handles the vendor prefix-list shape and drift', () => {
  const canonical = { creationTime: 'x', prefixes: [{ ipv4Prefix: '1.2.3.0/24' }, { ipv6Prefix: 'fd00::/8' }] };
  assert.deepEqual(extractPrefixes(canonical), ['1.2.3.0/24', 'fd00::/8']);
  const awsStyle = { prefixes: [{ ip_prefix: '5.6.7.0/24' }] };
  assert.deepEqual(extractPrefixes(awsStyle), ['5.6.7.0/24']);
  assert.deepEqual(extractPrefixes({}), []);
});

test('verifyBots classifies consistent, spoofed, absent ranges and fetch errors', async () => {
  const prefixBody = { prefixes: [{ ipv4Prefix: '203.0.113.0/24' }] };
  const fakeFetch = async (url) => {
    if (url === 'https://vendor.example/good.json') {
      return { ok: true, json: async () => prefixBody };
    }
    throw new Error('boom');
  };

  const results = await verifyBots(
    [
      { token: 'GoodBot', ranges: 'https://vendor.example/good.json', ips: ['203.0.113.5', '203.0.113.9'] },
      { token: 'FakeBot', ranges: 'https://vendor.example/good.json', ips: ['8.8.8.8'] },
      { token: 'OfflineBot', ranges: 'https://vendor.example/dead.json', ips: ['203.0.113.5'] },
      { token: 'NoRangesBot', ranges: null, ips: ['1.2.3.4'] },
    ],
    fakeFetch,
  );

  const good = results.find((r) => r.token === 'GoodBot');
  assert.equal(good.status, 'checked');
  assert.equal(good.share, 1);
  assert.equal(good.prefixes, 1);

  const fake = results.find((r) => r.token === 'FakeBot');
  assert.equal(fake.share, 0);
  assert.equal(fake.uniqueIps, 1);
  assert.deepEqual(fake.outsideSample, ['8.8.8.8']);

  const offline = results.find((r) => r.token === 'OfflineBot');
  assert.equal(offline.status, 'unavailable');
  assert.match(offline.error, /boom/);

  assert.equal(results.find((r) => r.token === 'NoRangesBot').status, 'no-ranges');
});

test('verifyBots reports MIXED when some IPs are outside vendor ranges', async () => {
  const fakeFetch = async () => ({
    ok: true,
    json: async () => ({ prefixes: [{ ipv4Prefix: '10.0.0.0/8' }, { ipv6Prefix: '2600:1f28:365:8000::/56' }] }),
  });
  const [r] = await verifyBots(
    [{ token: 'HalfBot', ranges: 'https://x.json', ips: ['10.1.1.1', '2600:1f28:365:8000::1', '9.9.9.9'] }],
    fakeFetch,
  );
  assert.equal(r.status, 'checked');
  assert.equal(r.fromVendorRanges, 2);
  assert.equal(r.uniqueIps, 3);
  assert.equal(r.outside, 1);
  assert.ok(Math.abs(r.share - 2 / 3) < 1e-9);
});
