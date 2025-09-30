#!/usr/bin/env node
const fs = require("fs/promises");
const path = require("path");

const { DEFAULT_REMOTE_DATASET_URL } = require("../src/config");
const { parseColonDelimitedDataset } = require("../src/lib/scanner");

const TARGET_PATH = path.join(__dirname, "..", "data", "compromised-packages.json");

async function readSource(source) {
  if (/^https?:/i.test(source)) {
    const response = await fetch(source, {
      headers: {
        accept: "application/json, text/plain;q=0.9"
      }
    });
    if (!response.ok) {
      throw new Error(`HTTP ${response.status} while fetching ${source}`);
    }
    return response.text();
  }
  return fs.readFile(path.resolve(source), "utf8");
}

function normalizeEntries(raw, label) {
  try {
    const parsed = JSON.parse(raw);
    if (Array.isArray(parsed)) {
      return parsed;
    }
  } catch (err) {
    // Not JSON, fall through to colon-delimited parsing
  }
  const colonEntries = parseColonDelimitedDataset(raw);
  if (colonEntries.length) {
    return colonEntries;
  }
  throw new Error(`Unable to parse dataset from ${label}; expected JSON array or colon-delimited list.`);
}

function dedupe(entries) {
  const map = new Map();
  for (const entry of entries) {
    if (!entry || typeof entry !== "object") continue;
    const { name, versions } = entry;
    if (!name || !Array.isArray(versions)) continue;
    if (!map.has(name)) {
      map.set(name, new Set());
    }
    for (const version of versions) {
      if (typeof version === "string") {
        const trimmed = version.trim();
        if (trimmed) {
          map.get(name).add(trimmed);
        }
      }
    }
  }
  return Array.from(map.entries())
    .map(([name, versions]) => ({ name, versions: Array.from(versions).sort() }))
    .sort((a, b) => a.name.localeCompare(b.name));
}

async function main() {
  const source = process.argv[2] || DEFAULT_REMOTE_DATASET_URL;
  const label = /^https?:/i.test(source) ? source : path.resolve(source);
  const raw = await readSource(source);
  const entries = dedupe(normalizeEntries(raw, label));
  const totalVersions = entries.reduce((acc, item) => acc + item.versions.length, 0);
  const output = JSON.stringify(entries, null, 4) + "\n";
  await fs.writeFile(TARGET_PATH, output, "utf8");
  console.log(`Wrote ${entries.length} packages / ${totalVersions} versions from ${label}`);
}

main().catch((err) => {
  console.error(err.stack || err.message);
  process.exitCode = 1;
});