# evvp-frontend

Frontend for the Early Vulnerability Verification Platform.

**Status: Planned**

Will consume the REST API exposed by `evvp-backend` at `http://localhost:8000/api/`.

## Planned stack
- React + TypeScript
- Tailwind CSS
- Recharts for signal timeline / category charts

## API endpoints it will consume

| Endpoint | Description |
|----------|-------------|
| `GET /api/stats` | Totals, platform counts, 7-day timeline |
| `GET /api/feed/<platform>?page=1&per_page=50` | reddit / github / blog / nvd / all |
| `GET /api/zerodays?days=7&min_score=8` | Pre-CVE zero-day candidates |
| `GET /api/cves?days=7&min_score=6` | CVE-tagged high-signal items |
| `GET /api/search?q=<query>` | Full-text search |
| `GET /api/item/<id>` | Single item detail |
| `GET /api/health` | Health check |
