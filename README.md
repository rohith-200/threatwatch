# ThreatWatch

Paste a GitHub repo and see which recent attacks could affect it, where, and how to fix them.

## Team rules
- Work on small feature branches: `a/<task>` for Person A, `b/<task>` for Person B (e.g. `a/ingest`, `b/report-screen`).
- Merge to `main` at least every 90 minutes. Pull `main` before you start each task.
- Never commit secrets. Real keys live only in `backend/.env`, which is gitignored.
- Talk before editing `shared/`, `fixtures/` or `backend/src/server.ts`.
