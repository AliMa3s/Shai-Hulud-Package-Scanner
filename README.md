# Shai-Hulud Controller

A Node.js toolkit that helps you spot indicators of compromise (IoCs) tied to the 2025 "Shai-Hulud" npm supply-chain attack. It now ships with both a command-line scanner and a lightweight UI so you can upload manifests or lockfiles directly from the browser and optionally follow a live JSON feed of compromised packages.

> **Data source:** the bundled dataset in `data/compromised-packages.json` is based on publicly shared research—including the continuously updated incident tracking from OX Security and advisories from other vendors. By default we also try to pull a remote feed (configurable) so new IoCs are picked up automatically; if that request fails we fall back to the bundled list.

## Web UI

```bash
npm install
npm start
```

The server launches at <http://localhost:3000>. From the page you can:

- Pick a local `package.json` or `package-lock.json` file and run the scan with a single click.
- Use the pre-filled dataset URL (defaults to `https://raw.githubusercontent.com/OX-Security/shai-hulud/main/iocs.json`, or whatever you set in `DEFAULT_DATASET_URL`) so every scan fetches the latest public indicators. You can erase or replace the URL to fall back to the bundled list or point at an internal feed.
- Follow quick links to public advisories that continue to publish newly compromised packages as the investigation evolves.

Each scan stays on your machine; the file is never forwarded beyond the local Node process. Results list every suspicious dependency along with the exact selector, section, and overlapping malicious versions so you can remediate quickly.

### Customising the default feed

```bash
# Example: point the UI/REST API at an internal feed every time the server boots
DEFAULT_DATASET_URL="https://security.example.com/shai-hulud/latest.json" npm start
```

The UI will show that URL in the input box by default, but anyone can clear or replace it before scanning.

## CLI usage

You can still run the scanner from the terminal for scripting and CI/CD enforcement:

```bash
npm run scan -- --file path/to/package.json
# or
node src/index.js --file path/to/package-lock.json --json
```

The CLI exits with code `1` when it detects IoCs. Use `--data` to point at an alternate dataset file or URL for a one-off run.

## Dataset maintenance

1. Update `data/compromised-packages.json` with the latest malicious `{ "name": "package", "versions": ["1.2.3"] }` tuples, **or**
2. Supply a remote JSON URL in the UI (or via `--data` in the CLI) so every scan pulls fresh entries from your trusted feed.

The `GET /api/dataset` endpoint exposes the bundled list if you want to diff your local copy against upstream sources, and `/api/config` returns the default feed currently in effect.

## Output interpretation

- **manifest-range** – Your manifest declares a range that overlaps malicious versions. Pin or exclude the affected releases before rebuilding.
- **manifest-exact** – Your manifest explicitly pins a compromised version.
- **manifest-name-only** – Your manifest references an affected package without a resolvable selector (e.g., alias). Manually verify the version in use.
- **lock-installed** – The lockfile shows a malicious version is already installed. Treat the environment as compromised: rotate secrets, reinstall from a clean machine, and redeploy.

## Helpful links

The UI surfaces these feeds, and you can bookmark them for ongoing incident updates:

- OX Security — [180+ NPM Packages Hit in Major Supply Chain Attack](https://www.ox.security/blog/npm-2-0-hack-40-npm-packages-hit-in-major-supply-chain-attack/)
- Black Duck Software — [The Shai-Hulud npm malware attack: A wake-up call for supply chain security](https://www.blackduck.com/blog/npm-malware-attack-shai-hulud-threat.html)

Keep the dataset fresh, wire the CLI into your pipelines, and use the UI for quick ad-hoc validation whenever a project looks suspicious.
