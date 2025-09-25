const express = require('express');
const path = require('path');
const multer = require('multer');
const {
  DEFAULT_DATASET_PATH,
  loadJsonFile,
  buildDataset,
  scanParsedJson,
  fetchDatasetFromUrl
} = require('./lib/scanner');
const { DEFAULT_REMOTE_DATASET_URL } = require('./config');

const app = express();
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 2 * 1024 * 1024 }
});

const PORT = process.env.PORT || 3000;

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, '..', 'public')));

app.get('/api/dataset', async (req, res, next) => {
  try {
    const { data } = await loadJsonFile(DEFAULT_DATASET_PATH, 'dataset');
    res.json({
      source: 'local',
      path: DEFAULT_DATASET_PATH,
      count: Array.isArray(data) ? data.length : 0,
      entries: data
    });
  } catch (err) {
    next(err);
  }
});

app.get('/api/resources', (req, res) => {
  res.json({
    resources: [
      {
        name: 'OX Security — Shai-Hulud incident dashboard',
        url: 'https://www.ox.security/blog/npm-2-0-hack-40-npm-packages-hit-in-major-supply-chain-attack/'
      },
      {
        name: 'Black Duck — Shai-Hulud npm malware overview',
        url: 'https://www.blackduck.com/blog/npm-malware-attack-shai-hulud-threat.html'
      }
    ]
  });
});

app.get('/api/config', (req, res) => {
  res.json({
    defaultDatasetUrl: DEFAULT_REMOTE_DATASET_URL || null
  });
});

app.post('/api/scan', upload.single('target'), async (req, res) => {
  try {
    if (!req.file) {
      res.status(400).json({ error: 'No package.json or package-lock.json file received.' });
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(req.file.buffer.toString('utf8'));
    } catch (err) {
      res.status(400).json({ error: 'Uploaded file is not valid JSON.' });
      return;
    }

    const userDatasetUrl = (req.body.datasetUrl || '').trim();
    const candidateUrls = [];
    if (userDatasetUrl) {
      candidateUrls.push({ url: userDatasetUrl, source: 'remote-custom' });
    } else if (DEFAULT_REMOTE_DATASET_URL) {
      candidateUrls.push({ url: DEFAULT_REMOTE_DATASET_URL, source: 'remote-default' });
    }

    let datasetEntries;
    let datasetMeta;
    let lastError;

    for (const candidate of candidateUrls) {
      try {
        datasetEntries = await fetchDatasetFromUrl(candidate.url);
        datasetMeta = {
          source: candidate.source,
          url: candidate.url
        };
        break;
      } catch (err) {
        lastError = err;
        datasetMeta = {
          source: 'local-fallback',
          path: DEFAULT_DATASET_PATH,
          fallbackFrom: candidate.url,
          error: err.message
        };
      }
    }

    if (!datasetEntries) {
      const { data } = await loadJsonFile(DEFAULT_DATASET_PATH, 'dataset');
      datasetEntries = data;
      if (!datasetMeta) {
        datasetMeta = {
          source: 'local',
          path: DEFAULT_DATASET_PATH
        };
      }
    }

    if (!Array.isArray(datasetEntries)) {
      res.status(400).json({ error: 'Dataset must be a JSON array of {name, versions} objects.' });
      return;
    }

    const dataset = buildDataset(datasetEntries);
    datasetMeta.entries = datasetEntries.length;
    datasetMeta.malformed = dataset.malformed.length;
    if (lastError) {
      datasetMeta.lastError = lastError.message;
    }

    const result = scanParsedJson(parsed, dataset.map);

    res.json({
      scannedAt: new Date().toISOString(),
      target: {
        originalName: req.file.originalname,
        size: req.file.size
      },
      dataset: datasetMeta,
      type: result.type,
      matches: result.matches
    });
  } catch (err) {
    res.status(500).json({ error: err.message || 'Unexpected server error' });
  }
});

app.use((err, req, res, _next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Unexpected server error' });
});

app.listen(PORT, () => {
  console.log(`Shai-Hulud UI available at http://localhost:${PORT}`);
});
