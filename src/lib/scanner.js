const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const semver = require('semver');

const DEFAULT_DATASET_PATH = path.join(__dirname, '..', '..', 'data', 'compromised-packages.json');
const VALID_MANIFEST_SECTIONS = [
  ['dependencies', 'runtime'],
  ['devDependencies', 'dev'],
  ['optionalDependencies', 'optional'],
  ['peerDependencies', 'peer'],
  ['bundledDependencies', 'bundled'],
  ['bundleDependencies', 'bundled']
];

async function loadJsonFile(filePath, label = 'file') {
  const absolute = path.resolve(filePath);
  let raw;
  try {
    raw = await fsp.readFile(absolute, 'utf8');
  } catch (err) {
    if (err.code === 'ENOENT') {
      throw new Error(`Unable to locate ${label} at ${absolute}`);
    }
    throw err;
  }
  try {
    return { data: JSON.parse(raw), absolute };
  } catch (err) {
    throw new Error(`Failed to parse JSON in ${absolute}: ${err.message}`);
  }
}

function buildDataset(entries) {
  const map = new Map();
  const malformed = [];
  for (const entry of entries || []) {
    if (!entry || typeof entry !== 'object') continue;
    const { name, versions } = entry;
    if (!name || !Array.isArray(versions)) {
      malformed.push(entry);
      continue;
    }
    const cleaned = versions
      .filter((v) => typeof v === 'string')
      .map((v) => v.trim())
      .filter(Boolean);
    map.set(name, new Set(cleaned));
  }
  return { map, malformed };
}

async function fetchDatasetFromUrl(url) {
  const response = await fetch(url, { headers: { accept: 'application/json' } });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const payload = await response.json();
  if (!Array.isArray(payload)) {
    throw new Error('Dataset must be a JSON array.');
  }
  return payload;
}

function parseNpmAlias(spec) {
  if (typeof spec !== 'string' || !spec.startsWith('npm:')) return null;
  const remainder = spec.slice(4);
  const atIndex = remainder.lastIndexOf('@');
  if (atIndex > 0) {
    const aliasName = remainder.slice(0, atIndex);
    const selector = remainder.slice(atIndex + 1) || null;
    return { name: aliasName, selector };
  }
  return { name: remainder, selector: null };
}

function matchRangeAgainstVersions(range, versions) {
  const validRange = semver.validRange(range, { includePrerelease: true });
  if (!validRange) return [];
  const hits = new Set();
  for (const version of versions) {
    if (!semver.valid(version, { includePrerelease: true })) continue;
    if (semver.satisfies(version, validRange, { includePrerelease: true })) {
      hits.add(version);
    }
  }
  return Array.from(hits).sort(semver.compare);
}

function evaluateManifestSpec(dependencyName, sectionLabel, spec, datasetMap, context = {}) {
  const findings = [];
  const datasetVersions = datasetMap.get(dependencyName);
  const record = (kind, targetName, selector, matches, aliasOf) => {
    findings.push({
      kind,
      dependency: dependencyName,
      section: sectionLabel,
      selector,
      target: targetName,
      aliasOf: aliasOf || null,
      matches,
      pattern: context.pattern || null
    });
  };

  if (datasetVersions) {
    if (typeof spec === 'string' && semver.validRange(spec, { includePrerelease: true })) {
      const matches = matchRangeAgainstVersions(spec, datasetVersions);
      if (matches.length) record('manifest-range', dependencyName, spec, matches, null);
    } else if (datasetVersions.has(spec)) {
      record('manifest-exact', dependencyName, spec, [spec], null);
    } else if (spec == null) {
      record('manifest-name-only', dependencyName, null, Array.from(datasetVersions), null);
    }
  }

  const alias = parseNpmAlias(spec);
  if (alias) {
    const aliasVersions = datasetMap.get(alias.name);
    if (aliasVersions) {
      if (alias.selector) {
        if (semver.validRange(alias.selector, { includePrerelease: true })) {
          const matches = matchRangeAgainstVersions(alias.selector, aliasVersions);
          if (matches.length) record('manifest-range', alias.name, alias.selector, matches, dependencyName);
        } else if (aliasVersions.has(alias.selector)) {
          record('manifest-exact', alias.name, alias.selector, [alias.selector], dependencyName);
        }
      } else {
        record('manifest-name-only', alias.name, null, Array.from(aliasVersions), dependencyName);
      }
    }
  }

  if (context.altTargets && Array.isArray(context.altTargets)) {
    for (const alt of context.altTargets) {
      const altVersions = datasetMap.get(alt);
      if (!altVersions) continue;
      const selector = typeof spec === 'string' ? spec : null;
      if (selector && semver.validRange(selector, { includePrerelease: true })) {
        const matches = matchRangeAgainstVersions(selector, altVersions);
        if (matches.length) record('manifest-range', alt, selector, matches, dependencyName);
      } else if (selector && altVersions.has(selector)) {
        record('manifest-exact', alt, selector, [selector], dependencyName);
      } else if (!selector) {
        record('manifest-name-only', alt, null, Array.from(altVersions), dependencyName);
      }
    }
  }

  return findings;
}

function normalizeResolutionKey(key) {
  if (typeof key !== 'string') return key;
  let cleaned = key.trim();
  cleaned = cleaned.replace(/^npm:/, '');
  cleaned = cleaned.replace(/\*\*?\//g, '');
  cleaned = cleaned.replace(/>/g, '/');
  cleaned = cleaned.replace(/\s+/g, '');
  const match = cleaned.match(/(@[^/]+\/[^/]+|[^/]+)$/);
  return match ? match[1] : cleaned;
}

function flattenResolutionEntries(key, value, bucket, trail = []) {
  if (typeof value === 'string') {
    const target = normalizeResolutionKey(key);
    const context = {
      pattern: [...trail, key].join(' -> ') || key,
      altTargets: target && target !== key ? [target] : []
    };
    bucket.push({ name: key, spec: value, context });
    if (target && target !== key) {
      bucket.push({ name: target, spec: value, context });
    }
    return;
  }
  if (Array.isArray(value)) {
    for (const item of value) {
      flattenResolutionEntries(key, item, bucket, trail);
    }
    return;
  }
  if (value && typeof value === 'object') {
    for (const [innerKey, innerValue] of Object.entries(value)) {
      flattenResolutionEntries(innerKey, innerValue, bucket, [...trail, key]);
    }
  }
}

function analyzeManifest(manifest, datasetMap) {
  const matches = [];
  for (const [section, label] of VALID_MANIFEST_SECTIONS) {
    const block = manifest?.[section];
    if (!block || typeof block !== 'object') continue;
    for (const [depName, spec] of Object.entries(block)) {
      const findings = evaluateManifestSpec(depName, label, spec, datasetMap);
      matches.push(...findings);
    }
  }

  const overrides = manifest?.overrides || manifest?.pnpm?.overrides;
  if (overrides && typeof overrides === 'object') {
    const flattened = [];
    for (const [key, value] of Object.entries(overrides)) {
      flattenResolutionEntries(key, value, flattened);
    }
    for (const entry of flattened) {
      const findings = evaluateManifestSpec(entry.name, 'override', entry.spec, datasetMap, entry.context);
      matches.push(...findings);
    }
  }

  if (manifest?.resolutions && typeof manifest.resolutions === 'object') {
    const flattened = [];
    for (const [key, value] of Object.entries(manifest.resolutions)) {
      flattenResolutionEntries(key, value, flattened);
    }
    for (const entry of flattened) {
      const findings = evaluateManifestSpec(entry.name, 'resolution', entry.spec, datasetMap, entry.context);
      matches.push(...findings);
    }
  }

  return matches;
}

function deriveNameFromPath(pkgPath) {
  if (!pkgPath || pkgPath === '') return null;
  const normalized = pkgPath.replace(/\\/g, '/');
  const segments = normalized.split('node_modules/').filter(Boolean);
  if (!segments.length) return normalized;
  const candidate = segments[segments.length - 1];
  if (candidate.startsWith('@')) {
    const scopeParts = candidate.split('/');
    return scopeParts.length >= 2 ? `${scopeParts[0]}/${scopeParts[1]}` : candidate;
  }
  return candidate;
}

function collectMatchesFromPackages(packages, datasetMap) {
  const matches = [];
  for (const [pkgPath, meta] of Object.entries(packages || {})) {
    if (!meta || typeof meta !== 'object') continue;
    const version = meta.version;
    if (!version || typeof version !== 'string') continue;
    const explicitName = meta.name;
    const derivedName = explicitName || deriveNameFromPath(pkgPath);
    if (!derivedName) continue;
    const versions = datasetMap.get(derivedName);
    if (versions && versions.has(version)) {
      matches.push({
        kind: 'lock-installed',
        name: derivedName,
        version,
        location: pkgPath || '(root)'
      });
    }
  }
  return matches;
}

function collectMatchesFromDependencies(depTree, datasetMap, ancestry = []) {
  if (!depTree || typeof depTree !== 'object') return [];
  const matches = [];
  for (const [name, info] of Object.entries(depTree)) {
    if (!info || typeof info !== 'object') continue;
    const version = info.version;
    const versions = datasetMap.get(name);
    if (version && versions && versions.has(version)) {
      matches.push({
        kind: 'lock-installed',
        name,
        version,
        location: [...ancestry, name].join(' > ') || name
      });
    }
    if (info.dependencies) {
      matches.push(...collectMatchesFromDependencies(info.dependencies, datasetMap, [...ancestry, name]));
    }
  }
  return matches;
}

function analyzeLockfile(lock, datasetMap) {
  const matches = [];
  if (lock?.packages && typeof lock.packages === 'object') {
    matches.push(...collectMatchesFromPackages(lock.packages, datasetMap));
  }
  if (lock?.dependencies && typeof lock.dependencies === 'object') {
    matches.push(...collectMatchesFromDependencies(lock.dependencies, datasetMap));
  }
  return matches;
}

function dedupeMatches(matches) {
  const seen = new Map();
  for (const match of matches || []) {
    const keyParts = [match.kind, match.name || match.dependency, match.version || match.selector, match.location || match.section, match.pattern || ''];
    const key = keyParts.filter(Boolean).join('|');
    if (!seen.has(key)) {
      seen.set(key, match);
    }
  }
  return Array.from(seen.values());
}

function detectFileType(parsed) {
  if (!parsed || typeof parsed !== 'object') return 'unknown';
  if (parsed.lockfileVersion || parsed.packages || (parsed.dependencies && !parsed.name && !parsed.version)) {
    return 'package-lock';
  }
  return 'package';
}

function formatTextReport(result) {
  const lines = [];
  lines.push(`Scan target: ${result.targetPath ?? '(memory)'}`);
  lines.push(`Dataset: ${result.datasetPath ?? '(in-memory dataset)'}`);
  lines.push(`File type: ${result.type}`);
  if (!result.matches.length) {
    lines.push('No known Shai-Hulud IoCs found in this file.');
  } else {
    lines.push(`Found ${result.matches.length} indicator(s):`);
    result.matches.forEach((match, idx) => {
      const prefix = `${idx + 1}.`;
      if (match.kind === 'manifest-range') {
        const aliasNote = match.aliasOf ? ` (alias of ${match.aliasOf})` : '';
        const patternNote = match.pattern ? ` [pattern: ${match.pattern}]` : '';
        lines.push(`${prefix} ${match.dependency} (${match.section}) -> ${match.target} selector "${match.selector}" overlaps malicious versions [${match.matches.join(', ')}]${aliasNote}${patternNote}`);
      } else if (match.kind === 'manifest-exact') {
        const aliasNote = match.aliasOf ? ` (alias of ${match.aliasOf})` : '';
        const patternNote = match.pattern ? ` [pattern: ${match.pattern}]` : '';
        lines.push(`${prefix} ${match.dependency} (${match.section}) pins ${match.target}@${match.selector}${aliasNote}${patternNote}`);
      } else if (match.kind === 'manifest-name-only') {
        const aliasNote = match.aliasOf ? ` (alias of ${match.aliasOf})` : '';
        const patternNote = match.pattern ? ` [pattern: ${match.pattern}]` : '';
        lines.push(`${prefix} ${match.dependency} (${match.section}) references ${match.target}; verify versions: [${match.matches.join(', ')}]${aliasNote}${patternNote}`);
      } else if (match.kind === 'lock-installed') {
        lines.push(`${prefix} ${match.name}@${match.version} installed at ${match.location}`);
      } else {
        lines.push(`${prefix} ${JSON.stringify(match)}`);
      }
    });
    lines.push('Recommended next steps: remove or downgrade the flagged versions, rotate exposed credentials, and redeploy from a clean environment.');
  }
  return lines.join('\n');
}

function scanParsedJson(parsed, datasetMap) {
  const type = detectFileType(parsed);
  const rawMatches = type === 'package'
    ? analyzeManifest(parsed, datasetMap)
    : analyzeLockfile(parsed, datasetMap);
  return { type, matches: dedupeMatches(rawMatches) };
}

async function scanFile(targetPath, datasetMap) {
  const { data: parsed } = await loadJsonFile(targetPath, 'target file');
  return scanParsedJson(parsed, datasetMap);
}

module.exports = {
  DEFAULT_DATASET_PATH,
  VALID_MANIFEST_SECTIONS,
  loadJsonFile,
  buildDataset,
  fetchDatasetFromUrl,
  parseNpmAlias,
  matchRangeAgainstVersions,
  evaluateManifestSpec,
  normalizeResolutionKey,
  flattenResolutionEntries,
  analyzeManifest,
  analyzeLockfile,
  dedupeMatches,
  detectFileType,
  formatTextReport,
  scanParsedJson,
  scanFile
};
