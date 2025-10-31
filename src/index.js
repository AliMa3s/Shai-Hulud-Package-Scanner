#!/usr/bin/env node
const path = require('path');
const readline = require('readline');
const {
  DEFAULT_DATASET_PATH,
  loadJsonFile,
  buildDataset,
  scanParsedJson,
  formatTextReport
} = require('./lib/scanner');
const { resolveDataset, isHttpUrl } = require('./lib/dataset');

function parseArgs(argv) {
  const args = argv.slice(2);
  const options = { flags: new Set() };
  for (let i = 0; i < args.length; i += 1) {
    const token = args[i];
    switch (token) {
      case '-f':
      case '--file':
        options.file = args[++i];
        break;
      case '-d':
      case '--data':
        options.dataset = args[++i];
        break;
      case '--json':
        options.flags.add('json');
        break;
      case '--quiet':
      case '-q':
        options.flags.add('quiet');
        break;
      case '--help':
      case '-h':
        options.flags.add('help');
        break;
      default:
        if (!token.startsWith('-') && !options.file) {
          options.file = token;
        } else {
          throw new Error(`Unknown argument: ${token}`);
        }
    }
  }
  return options;
}

async function promptForPath(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  const answer = await new Promise((resolve) => rl.question(question, (resp) => resolve(resp.trim())));
  rl.close();
  return answer;
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
    console.log(`Usage: node src/index.js [options]\n\nOptions:\n  -f, --file <path>      package.json or package-lock.json to scan\n  -d, --data <path|url>  override dataset JSON (file path or URL)\n      --json              emit JSON report instead of text\n  -q, --quiet            suppress non-critical output\n  -h, --help             show help`);
    return;
  }

  let targetPath = options.file;
  if (!targetPath) {
    targetPath = await promptForPath('Path to package.json or package-lock.json: ');
  }
  if (!targetPath) {
    console.error('No target file provided.');
    process.exit(2);
    return;
  }

  const { data: packageData, absolute: resolvedTarget } = await loadJsonFile(targetPath, 'target file');
  let datasetResult;
  try {
    datasetResult = await resolveDataset(options.dataset, options.flags.has('quiet'));
  } catch (err) {
    console.error(err.message);
    process.exit(2);
    return;
  }

  const dataset = buildDataset(datasetResult.entries);
  if (dataset.malformed.length && !options.flags.has('quiet')) {
    console.warn(`Warning: dataset has ${dataset.malformed.length} malformed entr${dataset.malformed.length === 1 ? 'y' : 'ies'} that were ignored.`);
  }

  const result = scanParsedJson(packageData, dataset.map);
  const report = {
    scannedAt: new Date().toISOString(),
    targetPath: resolvedTarget,
    datasetPath: datasetResult.meta.source === 'local-fallback'
      ? `${datasetResult.meta.path} (fallback from ${datasetResult.meta.fallbackFrom})`
      : datasetResult.identifier,
    datasetMeta: datasetResult.meta,
    type: result.type,
    matches: result.matches
  };

  if (options.flags.has('json')) {
    console.log(JSON.stringify(report, null, 2));
  } else {
    console.log(formatTextReport(report));
  }

  if (result.matches.length > 0) {
    process.exitCode = 1;
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error(err.message || err);
    process.exit(2);
  });
}
