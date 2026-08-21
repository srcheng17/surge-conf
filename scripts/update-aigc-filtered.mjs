#!/usr/bin/env node

import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import { isIP } from 'node:net';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

export const SOURCE_URL =
  'https://raw.githubusercontent.com/Rabbit-Spec/Surge/Master/Rules/AIGC.list';
export const DEFAULT_OUTPUT_PATH = 'surge/rules/AIGC-filtered.list';

const MINIMUM_RULE_COUNT = 50;
const MAXIMUM_RULE_COUNT = 500;
const MAXIMUM_SOURCE_BYTES = 128 * 1024;
const MAXIMUM_LINE_LENGTH = 1024;
const REQUIRED_ASN = 399358;
const EXCLUDED_ASNS = new Set([13335, 20473]);
const ALLOWED_RULE_TYPES = new Set([
  'DOMAIN',
  'DOMAIN-SUFFIX',
  'IP-ASN',
  'IP-CIDR',
  'IP-CIDR6',
]);

function canonicalizeParts(parts) {
  return parts.map((part, index) =>
    index === 0 || index >= 2 ? part.toUpperCase() : part,
  );
}

function validateDomain(value, lineNumber) {
  if (value.length > 253 || value.split('.').length < 2) {
    throw new Error(`Invalid domain at line ${lineNumber}: ${value}`);
  }

  for (const label of value.split('.')) {
    if (
      label.length < 1 ||
      label.length > 63 ||
      !/^[A-Z0-9](?:[A-Z0-9-]*[A-Z0-9])?$/i.test(label)
    ) {
      throw new Error(`Invalid domain at line ${lineNumber}: ${value}`);
    }
  }
}

function validateCidr(value, expectedFamily, lineNumber) {
  const match = value.match(/^(.+)\/(\d{1,3})$/);
  const maximumPrefix = expectedFamily === 4 ? 32 : 128;
  const prefix = match ? Number(match[2]) : Number.NaN;

  if (
    !match ||
    isIP(match[1]) !== expectedFamily ||
    !Number.isInteger(prefix) ||
    prefix < 0 ||
    prefix > maximumPrefix
  ) {
    throw new Error(`Invalid IPv${expectedFamily} CIDR at line ${lineNumber}: ${value}`);
  }
}

function parseRule(line, lineNumber) {
  const rawParts = line.split(',').map((part) => part.trim());
  const parts = canonicalizeParts(rawParts);
  const type = parts[0];

  if (!ALLOWED_RULE_TYPES.has(type)) {
    throw new Error(`Unsupported rule type at line ${lineNumber}: ${rawParts[0]}`);
  }

  if (type === 'DOMAIN' || type === 'DOMAIN-SUFFIX') {
    if (parts.length !== 2) {
      throw new Error(`Unexpected fields at line ${lineNumber}: ${line}`);
    }
    validateDomain(parts[1], lineNumber);
    return { canonical: `${type},${parts[1]}`, excluded: false, type };
  }

  if (type === 'IP-ASN') {
    if (!/^\d+$/.test(parts[1] ?? '')) {
      throw new Error(`Invalid ASN at line ${lineNumber}: ${parts[1] ?? ''}`);
    }
    const asn = Number(parts[1]);
    if (!Number.isSafeInteger(asn) || asn < 1 || asn > 4_294_967_295) {
      throw new Error(`Invalid ASN at line ${lineNumber}: ${parts[1]}`);
    }

    // Filter by parsed ASN so changes to spacing or trailing options cannot bypass it.
    if (EXCLUDED_ASNS.has(asn)) {
      return { canonical: `IP-ASN,${asn}`, excluded: true, type };
    }
    if (asn !== REQUIRED_ASN) {
      throw new Error(`Unreviewed ASN at line ${lineNumber}: ${asn}`);
    }
    if (parts.length !== 3 || parts[2] !== 'NO-RESOLVE') {
      throw new Error(`Unexpected IP-ASN options at line ${lineNumber}: ${line}`);
    }
    return {
      canonical: `IP-ASN,${asn},no-resolve`,
      excluded: false,
      type,
    };
  }

  if (parts.length !== 3 || parts[2] !== 'NO-RESOLVE') {
    throw new Error(`Unexpected ${type} options at line ${lineNumber}: ${line}`);
  }
  validateCidr(parts[1], type === 'IP-CIDR' ? 4 : 6, lineNumber);
  return {
    canonical: `${type},${parts[1]},no-resolve`,
    excluded: false,
    type,
  };
}

export function buildFilteredRuleSet(source) {
  if (Buffer.byteLength(source, 'utf8') > MAXIMUM_SOURCE_BYTES) {
    throw new Error(`Upstream response exceeds ${MAXIMUM_SOURCE_BYTES} bytes`);
  }
  if (/[\0-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(source)) {
    throw new Error('Upstream response contains control characters');
  }

  const lines = source.replace(/\r\n?/g, '\n').trimEnd().split('\n');
  if (lines.some((line) => line.length > MAXIMUM_LINE_LENGTH)) {
    throw new Error(`Upstream response contains a line over ${MAXIMUM_LINE_LENGTH} characters`);
  }

  const nameHeaders = lines.filter((line) => /^# NAME:\s*.+/.test(line));
  const totalHeaders = lines.filter((line) => /^# TOTAL:\s*\d+\s*$/.test(line));
  if (nameHeaders.length !== 1) {
    throw new Error(`Expected one NAME header; found ${nameHeaders.length}`);
  }
  if (totalHeaders.length !== 1) {
    throw new Error(`Expected one TOTAL header; found ${totalHeaders.length}`);
  }

  const parsedRules = [];
  for (const [index, line] of lines.entries()) {
    const trimmed = line.trim();
    if (trimmed === '' || trimmed.startsWith('#')) continue;
    parsedRules.push(parseRule(trimmed, index + 1));
  }

  if (
    parsedRules.length < MINIMUM_RULE_COUNT ||
    parsedRules.length > MAXIMUM_RULE_COUNT
  ) {
    throw new Error(
      `Upstream rule set has ${parsedRules.length} rules; expected ${MINIMUM_RULE_COUNT}-${MAXIMUM_RULE_COUNT}`,
    );
  }

  const declaredTotal = Number(totalHeaders[0].match(/\d+/)[0]);
  if (declaredTotal !== parsedRules.length) {
    throw new Error(
      `Upstream TOTAL is ${declaredTotal}, but ${parsedRules.length} active rules were found`,
    );
  }

  const canonicalRules = parsedRules.map((rule) => rule.canonical);
  if (new Set(canonicalRules).size !== canonicalRules.length) {
    throw new Error('Upstream rule set contains duplicate rules');
  }

  const filteredRules = parsedRules.filter((rule) => !rule.excluded);
  const requiredRules = filteredRules.filter(
    (rule) => rule.canonical === `IP-ASN,${REQUIRED_ASN},no-resolve`,
  );
  if (requiredRules.length !== 1) {
    throw new Error(`Expected one reviewed AS${REQUIRED_ASN} rule; found ${requiredRules.length}`);
  }

  const output = [
    '# NAME: Filtered AIGC rules',
    '# AUTHOR: Rabbit-Spec (upstream), srcheng17 (filter)',
    `# SOURCE: ${SOURCE_URL}`,
    `# BASE TOTAL: ${declaredTotal}`,
    `# FILTERED TOTAL: ${filteredRules.length}`,
    '# LOCAL FILTER: Removed IP-ASN 13335 (Cloudflare) and 20473 (Vultr/The Constant Company).',
    '# AUTO-GENERATED: Changes are managed by GitHub Actions.',
    '',
    ...filteredRules.map((rule) => rule.canonical),
  ];

  return `${output.join('\n')}\n`;
}

async function readLimitedBody(response) {
  const declaredLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(declaredLength) && declaredLength > MAXIMUM_SOURCE_BYTES) {
    throw new Error(`Upstream response exceeds ${MAXIMUM_SOURCE_BYTES} bytes`);
  }

  const reader = response.body.getReader();
  const chunks = [];
  let totalBytes = 0;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    totalBytes += value.byteLength;
    if (totalBytes > MAXIMUM_SOURCE_BYTES) {
      await reader.cancel();
      throw new Error(`Upstream response exceeds ${MAXIMUM_SOURCE_BYTES} bytes`);
    }
    chunks.push(value);
  }

  const body = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder('utf-8', { fatal: true }).decode(body);
}

async function fetchWithRetry(attempts = 3) {
  let lastError;
  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const response = await fetch(SOURCE_URL, {
        headers: { 'user-agent': 'srcheng17/surge-conf rule updater' },
        redirect: 'error',
        signal: AbortSignal.timeout(30_000),
      });
      if (!response.ok) {
        throw new Error(`HTTP ${response.status} ${response.statusText}`);
      }
      if (response.url !== SOURCE_URL) {
        throw new Error(`Unexpected final source URL: ${response.url}`);
      }
      const contentType = response.headers.get('content-type') ?? '';
      if (!contentType.toLowerCase().startsWith('text/plain')) {
        throw new Error(`Unexpected content type: ${contentType || '(missing)'}`);
      }
      return await readLimitedBody(response);
    } catch (error) {
      lastError = error;
      if (attempt < attempts) {
        await new Promise((resolve) => setTimeout(resolve, attempt * 1_000));
      }
    }
  }

  throw new Error(`Failed to download ${SOURCE_URL}: ${lastError.message}`);
}

async function writeAtomically(outputPath, content) {
  const resolvedPath = path.resolve(outputPath);
  const temporaryPath = `${resolvedPath}.tmp-${process.pid}`;

  await mkdir(path.dirname(resolvedPath), { recursive: true });
  try {
    await writeFile(temporaryPath, content, { encoding: 'utf8', mode: 0o644 });
    await rename(temporaryPath, resolvedPath);
  } finally {
    await unlink(temporaryPath).catch(() => {});
  }
}

async function main() {
  const sourceFile = process.env.AIGC_SOURCE_FILE;
  const outputPath = process.env.AIGC_OUTPUT_PATH ?? DEFAULT_OUTPUT_PATH;
  const source = sourceFile
    ? await readFile(path.resolve(sourceFile), 'utf8')
    : await fetchWithRetry();
  const filtered = buildFilteredRuleSet(source);

  await writeAtomically(outputPath, filtered);
  console.log(`Updated ${outputPath} from ${sourceFile ?? SOURCE_URL}`);
}

const entryPoint = process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href;
if (entryPoint === import.meta.url) {
  main().catch((error) => {
    console.error(error.message);
    process.exitCode = 1;
  });
}
