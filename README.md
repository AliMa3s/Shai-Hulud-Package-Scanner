# Shai-Hulud Controller

A Node.js toolkit that helps you spot indicators of compromise (IoCs) tied to the 2025 "Shai-Hulud" npm supply-chain attack. It now ships with both a command-line scanner and a lightweight UI so you can upload manifests or lockfiles directly from the browser and optionally follow a live JSON feed of compromised packages.

> **Data source:** The bundled dataset in `data/compromised-packages.json` (snapshot dated 2025-09-30) consolidates 239 packages / 604 malicious versions pulled from StepSecurity, Wiz.io, Semgrep, JFrog, Socket.dev, and CISA advisories via the community-maintained [Cobenian/shai-hulud-detect](https://github.com/Cobenian/shai-hulud-detect) feed. At runtime we also fetch [`https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt`](https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt); the loader now accepts either that colon-delimited list or a JSON array and falls back to the bundled snapshot if the network request fails.

## Web UI

```bash
npm install
npm start
```

The server launches at <http://localhost:3000>. From the page you can:

- Pick a local `package.json` or `package-lock.json` file and run the scan with a single click.
- Use the pre-filled dataset URL (defaults to [`https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt`](https://raw.githubusercontent.com/Cobenian/shai-hulud-detect/main/compromised-packages.txt), or whatever you set in `DEFAULT_DATASET_URL`) so every scan fetches the latest public indicators. Paste any JSON array or colon-delimited feed (or clear it) to fall back to the bundled list or point at an internal feed.
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

1. Run `npm run data:update` to regenerate `data/compromised-packages.json` from the upstream feed (pass an alternate URL or file path with `npm run data:update -- <source>` when needed).
2. Point the UI/CLI at any JSON array **or** colon-delimited feed via the input box or the `--data` flag to pull a different set of IoCs for a one-off scan.

The `GET /api/dataset` endpoint exposes the bundled list if you want to diff your local copy against upstream sources, and `/api/config` returns the default feed currently in effect.

## Output interpretation

- **manifest-range** – Your manifest declares a range that overlaps malicious versions. Pin or exclude the affected releases before rebuilding.
- **manifest-exact** – Your manifest explicitly pins a compromised version.
- **manifest-name-only** – Your manifest references an affected package without a resolvable selector (e.g., alias). Manually verify the version in use.
- **lock-installed** – The lockfile shows a malicious version is already installed. Treat the environment as compromised: rotate secrets, reinstall from a clean machine, and redeploy.

## Helpful links

The UI surfaces these feeds, and you can bookmark them for ongoing incident updates:

- Cobenian/shai-hulud-detect - [Community-maintained package/version feed](https://github.com/Cobenian/shai-hulud-detect)
- StepSecurity - [Shai-Hulud: Self-Replicating Worm Compromises 500+ NPM Packages](https://www.stepsecurity.io/blog/ctrl-tinycolor-and-40-npm-packages-compromised)
- Wiz.io - [Shai-Hulud npm supply chain attack deep dive](https://www.wiz.io/blog/shai-hulud-npm-supply-chain-attack)
- JFrog - [New compromised packages detected in the Shai-Hulud campaign](https://jfrog.com/blog/shai-hulud-npm-supply-chain-attack-new-compromised-packages-detected/)
- Semgrep - [Security advisory: npm packages using secret scanning tools to steal credentials](https://semgrep.dev/blog/2025/security-advisory-npm-packages-using-secret-scanning-tools-to-steal-credentials/)
- Socket.dev - [Ongoing supply chain attack targets CrowdStrike npm packages](https://socket.dev/blog/ongoing-supply-chain-attack-targets-crowdstrike-npm-packages)
- CISA - [Widespread Supply Chain Compromise Impacting npm Ecosystem](https://www.cisa.gov/news-events/alerts/2025/09/23/widespread-supply-chain-compromise-impacting-npm-ecosystem)
- SecurityWeek - [Shai-Hulud supply chain attack worm used to steal secrets](https://www.securityweek.com/shai-hulud-supply-chain-attack-worm-used-to-steal-secrets-180-npm-packages-hit/)

Keep the dataset fresh, wire the CLI into your pipelines, and use the UI for quick ad-hoc validation whenever a project looks suspicious.
