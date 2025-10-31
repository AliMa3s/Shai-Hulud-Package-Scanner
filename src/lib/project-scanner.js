const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');
const {
  MALICIOUS_SHA256,
  SUSPICIOUS_WORKFLOW_FILENAMES,
  SUSPICIOUS_POSTINSTALL_KEYWORDS,
  SUSPICIOUS_CONTENT_PATTERNS,
  TRUFFLEHOG_PATTERNS,
  DEFAULT_DIR_EXCLUSIONS,
  HASHABLE_EXTENSIONS,
  TEXT_FILE_EXTENSIONS
} = require('./iocs');
const { scanParsedJson } = require('./scanner');

const MAX_TEXT_BYTES = 512 * 1024;
const SELF_CONTENT_ALLOWLIST = new Set([
  'src/lib/iocs.js'
]);

async function computeSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('error', reject);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
  });
}

async function readFileLimited(filePath, limit = MAX_TEXT_BYTES) {
  const handle = await fsp.open(filePath, 'r');
  try {
    const stats = await handle.stat();
    const length = Math.min(limit, stats.size);
    const buffer = Buffer.alloc(length);
    await handle.read(buffer, 0, length, 0);
    return buffer.toString('utf8');
  } finally {
    await handle.close();
  }
}

async function walkDirectory(rootDir, options, visitor) {
  const stack = [rootDir];
  const { excludeDirs = DEFAULT_DIR_EXCLUSIONS, followSymlinks = false } = options || {};

  while (stack.length) {
    const current = stack.pop();
    let dir;
    try {
      dir = await fsp.opendir(current);
    } catch (err) {
      continue;
    }
    for await (const dirent of dir) {
      try {
        const entryPath = path.join(current, dirent.name);
        if (dirent.isSymbolicLink() && !followSymlinks) {
          continue;
        }
        if (dirent.isDirectory()) {
          if (excludeDirs && excludeDirs.has(dirent.name)) {
            continue;
          }
          stack.push(entryPath);
          continue;
        }
        if (!dirent.isFile()) {
          continue;
        }
        await visitor(entryPath, dirent);
      } catch (err) {
        // Ignore traversal errors for individual entries
      }
    }
  }
}

function determineManifestSeverity(match) {
  switch (match.kind) {
    case 'manifest-exact':
    case 'lock-installed':
      return 'high';
    case 'manifest-range':
    case 'manifest-name-only':
      return 'medium';
    default:
      return 'medium';
  }
}

function formatManifestMessage(match) {
  if (match.kind === 'manifest-exact') {
    const aliasNote = match.aliasOf ? ` (alias of ${match.aliasOf})` : '';
    return `Dependency ${match.dependency} pins ${match.target}@${match.selector}${aliasNote} which is confirmed compromised.`;
  }
  if (match.kind === 'manifest-range') {
    const aliasNote = match.aliasOf ? ` (alias of ${match.aliasOf})` : '';
    const patternNote = match.pattern ? ` [pattern: ${match.pattern}]` : '';
    return `Dependency ${match.dependency} allows ${match.target}@${match.selector}${aliasNote}${patternNote}; overlaps malicious versions: ${match.matches.join(', ')}.`;
  }
  if (match.kind === 'manifest-name-only') {
    const aliasNote = match.aliasOf ? ` (alias of ${match.aliasOf})` : '';
    return `Dependency ${match.dependency} references ${match.target}${aliasNote}; review installed versions manually.`;
  }
  if (match.kind === 'lock-installed') {
    return `Lockfile installs ${match.name}@${match.version} at ${match.location}.`;
  }
  return `Potential issue detected: ${JSON.stringify(match)}`;
}

function createFindingAggregator() {
  const findings = [];
  const counts = { high: 0, medium: 0, low: 0 };
  return {
    add(finding) {
      const { severity } = finding;
      if (!counts[severity]) {
        counts[severity] = 0;
      }
      counts[severity] += 1;
      findings.push(finding);
    },
    getFindings() {
      return findings;
    },
    getCounts() {
      return counts;
    }
  };
}

async function scanProject(rootDir, datasetMap, options = {}) {
  const absoluteRoot = path.resolve(rootDir);
  const includeNodeModules = Boolean(options.includeNodeModules);
  const excludeDirs = new Set(DEFAULT_DIR_EXCLUSIONS);
  if (includeNodeModules) {
    excludeDirs.delete('node_modules');
  }
  if (Array.isArray(options.additionalExcludes)) {
    for (const entry of options.additionalExcludes) {
      excludeDirs.add(entry);
    }
  }

  const aggregator = createFindingAggregator();
  const stats = {
    filesHashed: 0,
    contentScanned: 0,
    manifestsScanned: 0
  };
  const seenManifestMatches = new Set();

  await walkDirectory(absoluteRoot, { excludeDirs }, async (filePath, dirent) => {
    const relativePath = path.relative(absoluteRoot, filePath) || path.basename(filePath);
    const normalizedRelative = relativePath.split(path.sep).join('/');
    const baseName = dirent.name;
    const ext = path.extname(baseName).toLowerCase();

    if (SUSPICIOUS_WORKFLOW_FILENAMES.includes(baseName)) {
      aggregator.add({
        severity: 'high',
        type: 'workflow',
        message: 'Known malicious workflow filename detected.',
        path: relativePath
      });
    }

    if (HASHABLE_EXTENSIONS.has(ext)) {
      try {
        const hash = await computeSha256(filePath);
        stats.filesHashed += 1;
        if (MALICIOUS_SHA256.includes(hash)) {
          aggregator.add({
            severity: 'high',
            type: 'malicious-hash',
            message: `File hash matches known Shai-Hulud payload (${hash}).`,
            path: relativePath,
            details: { hash }
          });
        }
      } catch (err) {
        // ignore hashing errors
      }
    }

    let cachedContent;
    const ensureContent = async () => {
      if (cachedContent === undefined) {
        try {
          cachedContent = await readFileLimited(filePath);
          stats.contentScanned += 1;
        } catch (err) {
          cachedContent = null;
        }
      }
      return cachedContent;
    };

    if (!SELF_CONTENT_ALLOWLIST.has(normalizedRelative) && (TEXT_FILE_EXTENSIONS.has(ext) || SUSPICIOUS_WORKFLOW_FILENAMES.includes(baseName))) {
      const content = await ensureContent();
      if (typeof content === 'string' && content.length) {
        for (const patternInfo of SUSPICIOUS_CONTENT_PATTERNS) {
          patternInfo.pattern.lastIndex = 0;
          if (patternInfo.pattern.test(content)) {
            aggregator.add({
              severity: patternInfo.severity,
              type: 'suspicious-content',
              message: patternInfo.label,
              path: relativePath
            });
          }
        }
        for (const pattern of TRUFFLEHOG_PATTERNS) {
          pattern.lastIndex = 0;
          if (pattern.test(content)) {
            aggregator.add({
              severity: 'medium',
              type: 'trufflehog',
              message: 'Potential trufflehog credential scanning activity detected.',
              path: relativePath
            });
            break;
          }
        }
      }
    }

    if (baseName === 'package.json') {
      let parsed;
      try {
        const raw = await fsp.readFile(filePath, 'utf8');
        parsed = JSON.parse(raw);
      } catch (err) {
        aggregator.add({
          severity: 'low',
          type: 'manifest-error',
          message: `Unable to parse package.json (${err.message}).`,
          path: relativePath
        });
        return;
      }

      stats.manifestsScanned += 1;
      const postinstall = parsed?.scripts?.postinstall;
      if (typeof postinstall === 'string') {
        for (const keyword of SUSPICIOUS_POSTINSTALL_KEYWORDS) {
          if (postinstall.includes(keyword)) {
            aggregator.add({
              severity: 'high',
              type: 'postinstall',
              message: `Suspicious postinstall script: "${postinstall.trim()}"`,
              path: relativePath
            });
            break;
          }
        }
      }

      if (datasetMap) {
        const matches = scanParsedJson(parsed, datasetMap);
        for (const match of matches.matches) {
          const key = `${relativePath}|${match.kind}|${match.name || match.dependency}|${match.selector || match.version}|${match.pattern || ''}`;
          if (seenManifestMatches.has(key)) {
            continue;
          }
          seenManifestMatches.add(key);
          const severity = determineManifestSeverity(match);
          const message = formatManifestMessage(match);
          aggregator.add({
            severity,
            type: 'manifest',
            path: relativePath,
            message,
            details: match
          });
        }
      }
      return;
    }

    if (baseName === 'package-lock.json' || baseName === 'npm-shrinkwrap.json') {
      let parsed;
      try {
        const raw = await fsp.readFile(filePath, 'utf8');
        parsed = JSON.parse(raw);
      } catch (err) {
        aggregator.add({
          severity: 'low',
          type: 'manifest-error',
          message: `Unable to parse ${baseName} (${err.message}).`,
          path: relativePath
        });
        return;
      }

      stats.manifestsScanned += 1;
      if (datasetMap) {
        const matches = scanParsedJson(parsed, datasetMap);
        for (const match of matches.matches) {
          const key = `${relativePath}|${match.kind}|${match.name || match.dependency}|${match.selector || match.version}|${match.location || ''}`;
          if (seenManifestMatches.has(key)) {
            continue;
          }
          seenManifestMatches.add(key);
          const severity = determineManifestSeverity(match);
          const message = formatManifestMessage(match);
          aggregator.add({
            severity,
            type: 'lockfile',
            path: relativePath,
            message,
            details: match
          });
        }
      }
    }
  });

  return {
    targetPath: absoluteRoot,
    counts: aggregator.getCounts(),
    findings: aggregator.getFindings(),
    stats
  };
}

module.exports = {
  scanProject
};
