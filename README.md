# ThreatWatch 

**Paste a GitHub repo and see which newly published threats can actually reach your code, on which line, and what to fix first.**

Built at the **Cyberdefence Hackathon** hosted by Tokens& at AWS Builder Loft.

## Why

Hundreds of new npm vulnerabilities are published every month. Most tools only tell you a vulnerable version is installed, not whether your code can actually be hit, so real risks get lost in the noise. ThreatWatch filters them down to the few that matter.

## How it works

1. **Read dependencies** from the repo's `package.json` and `package-lock.json` on GitHub.
2. **Search live threat data:** OSV, GitHub advisories, CISA Known Exploited Vulnerabilities (KEV) and EPSS exploit scores.
3. **Check the code** with custom Semgrep rules, each tied to specific advisories, to find the exact file and line that reaches a vulnerability.
4. **Classify and score:** each alert is *likely affected* (vulnerable version plus code evidence) or *potentially affected* (vulnerable version, no matching code), with a transparent risk score.
5. **Explain the fix** with AkashML. Every AI answer is verified against the evidence, with safe fallback advice if a check fails.
6. **Store every analysis** in ClickHouse for history and "new since last analysis".

## Safety

- Never runs the analyzed repo's code: no installs, static analysis only.
- No source code is sent to the AI or written to logs, only file names and line numbers.
- Results say "likely" or "potentially affected based on evidence", never "breached".

## Tech stack

Node.js + TypeScript + Fastify · Next.js · Semgrep · ClickHouse · AkashML · OSV · CISA KEV · EPSS

## Run locally

**Requirements:** Node.js 20+, Docker, Git, Semgrep.

```bash
# 1. Start ClickHouse
docker run -d --name tw-clickhouse -p 8123:8123 \
  -e CLICKHOUSE_USER=tw -e CLICKHOUSE_PASSWORD=tw clickhouse/clickhouse-server

# 2. Backend (port 4000)
cd backend
cp .env.example .env    # fill in the keys below
npm install
npm run dev

# 3. Frontend (port 3000), in a second terminal
cd frontend
npm install
npm run dev
```

Open http://localhost:3000 and paste a public npm repo, e.g. `https://github.com/rohith-200/acme-checkout-api` (our intentionally vulnerable demo app).

**`backend/.env`:**

| Variable | Purpose |
|---|---|
| `GITHUB_TOKEN` | Read-only GitHub token for public repos |
| `AKASHML_API_KEY`, `AKASHML_BASE_URL`, `AKASHML_MODEL` | AI explanations |
| `CLICKHOUSE_URL` | e.g. `http://tw:tw@localhost:8123` |
| `SEMGREP_BIN` | Optional: path to Semgrep if it isn't on your PATH |

## Limitations

npm projects only, a curated Semgrep rule set, and on-demand analysis rather than continuous monitoring.

## Team

Rohith and Naman

## Thanks

Tokens&, AWS Builder Loft, and our sponsors: ClickHouse, Semgrep, Guild AI, Akash AI, ElevenLabs, OpenAI and AWS.
