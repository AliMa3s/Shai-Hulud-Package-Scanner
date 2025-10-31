#!/usr/bin/env node
const path = require('path');
const { buildDataset } = require('./lib/scanner');
const { resolveDataset } = require('./lib/dataset');
const { scanProject } = require('./lib/project-scanner');

const SEVERITY_ORDER = { high: 0, medium: 1, low: 2 };

function parseArgs(argv) {
  const args = argv.slice(2);
  const options = {
    flags: new Set()
  };
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    switch (token) {
      case '-d':
      case '--data':
        options.dataset = args[++i];
        break;
      case '--json':
        options.json = true;
        break;
      case '--quiet':
      case '-q':
        options.quiet = true;
        break;
      case '--include-node-modules':
        options.includeNodeModules = true;
        break;
      case '--help':
      case '-h':
        options.flags.add('help');
        break;
      default:
        if (!token.startsWith('-') && !options.directory) {
          options.directory = token;
        } else {
          throw new Error(`Unknown argument: ${token}`);
        }
    }
  }
  return options;
}

function showHelp() {
  console.log(`Usage: node src/project-scan.js [options] <directory>

Options:
  -d, --data <path|url>     Override dataset JSON (file path or URL)
      --json                Emit JSON report instead of text
  -q, --quiet               Suppress dataset fetch warnings
      --include-node-modules
                            Scan node_modules directory (slower)
  -h, --help                Show help

Examples:
  node src/project-scan.js .
  node src/project-scan.js --include-node-modules ../some-project
  node src/project-scan.js -d ./data/compromised-packages.json ..`);
}

function formatDatasetMeta(meta) {
  if (!meta) return 'Dataset: (none)';
  if (meta.source === 'remote-custom' || meta.source === 'remote-default') {
    return `Dataset source: ${meta.source} (${meta.url})`;
  }
  if (meta.source === 'local-fallback') {
    return `Dataset source: local fallback (${meta.path}) [failed to load ${meta.fallbackFrom}: ${meta.lastError ?? 'unknown error'}]`;
  }
  return `Dataset source: ${meta.source} (${meta.path ?? meta.url ?? 'unknown'})`;
}

function formatProjectReport(report) {
  const lines = [];
  lines.push(`Scan target: ${report.targetPath}`);
  lines.push(formatDatasetMeta(report.dataset));
  lines.push(`Dataset entries: ${report.dataset?.entries ?? 0}${report.dataset?.malformed ? ` (ignored ${report.dataset.malformed} malformed)` : ''}`);
  lines.push(`File coverage: ${report.stats.manifestsScanned} manifest(s), ${report.stats.filesHashed} hash checks, ${report.stats.contentScanned} content checks`);
  lines.push(`Findings: ${report.counts.high} high / ${report.counts.medium} medium / ${report.counts.low} low`);
  lines.push('');

  const findings = [...report.findings].sort((a, b) => {
    const severityDiff = (SEVERITY_ORDER[a.severity] ?? 99) - (SEVERITY_ORDER[b.severity] ?? 99);
    if (severityDiff !== 0) return severityDiff;
    if (a.type !== b.type) return a.type.localeCompare(b.type);
    return a.path.localeCompare(b.path);
  });

  if (!findings.length) {
    lines.push('No known Shai-Hulud indicators were detected in this project.');
    return lines.join('\n');
  }

  const severityLabels = {
    high: 'HIGH RISK',
    medium: 'MEDIUM RISK',
    low: 'LOW RISK'
  };

  for (const severity of ['high', 'medium', 'low']) {
    const subset = findings.filter((item) => item.severity === severity);
    if (!subset.length) continue;
    lines.push(`${severityLabels[severity]} indicators:`);
    subset.forEach((finding) => {
      lines.push(`  - ${finding.path}: ${finding.message}`);
    });
    lines.push('');
  }

  lines.push('Recommended next steps: remediate high-risk findings immediately, investigate medium-risk signals, and rerun scans after mitigation.');
  return lines.join('\n');
}

async function main() {
  let options;
  try {
    options = parseArgs(process.argv);
  } catch (err) {
    console.error(err.message);
    process.exit(2);
    return;
  }

  if (options.flags.has('help')) {
    showHelp();
    return;
  }

  if (!options.directory) {
    console.error('No directory provided. Pass the project root you want to scan.');
    process.exit(2);
    return;
  }

  const targetDir = path.resolve(options.directory);
  let datasetResult;
  try {
    datasetResult = await resolveDataset(options.dataset, { quiet: options.quiet });
  } catch (err) {
    console.error(err.message);
    process.exit(2);
    return;
  }

  const dataset = buildDataset(datasetResult.entries);
  const projectReport = await scanProject(targetDir, dataset.map, {
    includeNodeModules: options.includeNodeModules
  });

  const output = {
    scannedAt: new Date().toISOString(),
    targetPath: projectReport.targetPath,
    dataset: {
      ...datasetResult.meta,
      identifier: datasetResult.identifier,
      entries: datasetResult.entries.length,
      malformed: dataset.malformed.length
    },
    counts: projectReport.counts,
    findings: projectReport.findings,
    stats: projectReport.stats
  };

  if (options.json) {
    console.log(JSON.stringify(output, null, 2));
  } else {
    console.log(formatProjectReport(output));
  }

  if (output.counts.high > 0) {
    process.exitCode = 1;
  } else if (output.counts.medium > 0) {
    process.exitCode = 2;
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err.message || err);
    process.exit(2);
  });
}
