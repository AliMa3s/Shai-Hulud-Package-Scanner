const path = require('path');
const {
  DEFAULT_DATASET_PATH,
  loadJsonFile,
  fetchDatasetFromUrl
} = require('./scanner');
const { DEFAULT_REMOTE_DATASET_URL } = require('../config');

const isHttpUrl = (value) => typeof value === 'string' && /^https?:\/\//i.test(value);

async function resolveDataset(datasetArg, { quiet = false } = {}) {
  const candidateUrls = [];
  if (datasetArg && isHttpUrl(datasetArg)) {
    candidateUrls.push({ url: datasetArg, source: 'remote-custom' });
  } else if (!datasetArg && DEFAULT_REMOTE_DATASET_URL) {
    candidateUrls.push({ url: DEFAULT_REMOTE_DATASET_URL, source: 'remote-default' });
  }

  let datasetEntries;
  let datasetMeta;
  let identifier;
  let lastError;

  for (const candidate of candidateUrls) {
    try {
      datasetEntries = await fetchDatasetFromUrl(candidate.url);
      datasetMeta = { source: candidate.source, url: candidate.url };
      identifier = candidate.url;
      break;
    } catch (err) {
      lastError = err;
      if (!quiet) {
        console.warn(`Failed to fetch dataset from ${candidate.url}: ${err.message}`);
      }
    }
  }

  if (!datasetEntries) {
    const datasetPath = datasetArg && !isHttpUrl(datasetArg)
      ? path.resolve(datasetArg)
      : DEFAULT_DATASET_PATH;
    const { data, absolute } = await loadJsonFile(datasetPath, 'dataset');
    datasetEntries = data;
    identifier = absolute;
    if (candidateUrls.length && lastError) {
      datasetMeta = {
        source: 'local-fallback',
        path: absolute,
        fallbackFrom: candidateUrls[0].url,
        lastError: lastError.message
      };
    } else {
      datasetMeta = {
        source: 'local',
        path: absolute
      };
    }
  }

  if (!Array.isArray(datasetEntries)) {
    throw new Error('Dataset must be a JSON array of {name, versions}.');
  }

  datasetMeta.entries = datasetEntries.length;
  return { entries: datasetEntries, identifier, meta: datasetMeta };
}

module.exports = {
  resolveDataset,
  isHttpUrl
};
