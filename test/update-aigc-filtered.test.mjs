import assert from 'node:assert/strict';
import test from 'node:test';

import { buildFilteredRuleSet } from '../scripts/update-aigc-filtered.mjs';

function upstreamFixture({
  declaredTotalOffset = 0,
  extraHeaders = [],
  extraRules = [],
  lineEnding = '\n',
  updated = '2026.08.21 04:35:17',
} = {}) {
  const rules = [
    ...Array.from({ length: 60 }, (_, index) =>
      `DOMAIN-SUFFIX,service-${index}.example`,
    ),
    'IP-ASN,13335,no-resolve',
    'IP-ASN,20473,no-resolve',
    'IP-ASN,399358,no-resolve',
    'IP-CIDR,192.0.2.1/32,no-resolve',
    'IP-CIDR6,2001:db8::/32,no-resolve',
    ...extraRules,
  ];
  const lines = [
    '# NAME: Test AIGC rules',
    '# AUTHOR: Test',
    `# UPDATED: ${updated}`,
    `# TOTAL: ${rules.length + declaredTotalOffset}`,
    ...extraHeaders,
    '',
    ...rules,
  ];
  return lines.join(lineEnding);
}

test('removes target ASNs by parsed value and keeps reviewed IP rules', () => {
  const source = upstreamFixture().replace(
    'IP-ASN,13335,no-resolve',
    ' ip-asn, 13335 ',
  );
  const output = buildFilteredRuleSet(source);

  assert.doesNotMatch(output, /^IP-ASN,13335(?:,|$)/m);
  assert.doesNotMatch(output, /^IP-ASN,20473(?:,|$)/m);
  assert.match(output, /^IP-ASN,399358,no-resolve$/m);
  assert.match(output, /^IP-CIDR,192\.0\.2\.1\/32,no-resolve$/m);
  assert.match(output, /^IP-CIDR6,2001:db8::\/32,no-resolve$/m);
  assert.match(output, /^# BASE TOTAL: 65$/m);
  assert.match(output, /^# FILTERED TOTAL: 63$/m);
});

test('ignores dynamic upstream timestamps and produces deterministic output', () => {
  const first = buildFilteredRuleSet(upstreamFixture({ lineEnding: '\r\n' }));
  const second = buildFilteredRuleSet(
    upstreamFixture({ updated: '2026.08.22 04:35:17' }),
  );

  assert.equal(first, second);
  assert.equal(first.includes('\r'), false);
  assert.equal(first.includes('# UPDATED:'), false);
  assert.equal(first.endsWith('\n'), true);
});

test('rejects unsupported rule types and unreviewed ASNs', () => {
  assert.throws(
    () => buildFilteredRuleSet(upstreamFixture({ extraRules: ['FINAL,DIRECT'] })),
    /Unsupported rule type/,
  );
  assert.throws(
    () =>
      buildFilteredRuleSet(
        upstreamFixture({ extraRules: ['IP-ASN,64512,no-resolve'] }),
      ),
    /Unreviewed ASN/,
  );
});

test('rejects invalid domains, CIDRs, headers, and control characters', () => {
  assert.throws(
    () => buildFilteredRuleSet(upstreamFixture({ extraRules: ['DOMAIN-SUFFIX,com'] })),
    /Invalid domain/,
  );
  assert.throws(
    () =>
      buildFilteredRuleSet(
        upstreamFixture({ extraRules: ['IP-CIDR,192.0.2.1/99,no-resolve'] }),
      ),
    /Invalid IPv4 CIDR/,
  );
  assert.throws(
    () =>
      buildFilteredRuleSet(
        upstreamFixture({ extraHeaders: ['# TOTAL: 65'] }),
      ),
    /Expected one TOTAL header/,
  );
  assert.throws(
    () => buildFilteredRuleSet(`${upstreamFixture()}\0`),
    /control characters/,
  );
});

test('rejects mismatched totals and oversized rule sets', () => {
  assert.throws(
    () => buildFilteredRuleSet(upstreamFixture({ declaredTotalOffset: 1 })),
    /TOTAL is 66, but 65 active rules were found/,
  );
  assert.throws(
    () =>
      buildFilteredRuleSet(
        upstreamFixture({
          extraRules: Array.from(
            { length: 440 },
            (_, index) => `DOMAIN,extra-${index}.example`,
          ),
        }),
      ),
    /expected 50-500/,
  );
});
