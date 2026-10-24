# evvp-frontend — optional React prototype (NOT the supported UI)

**The supported dashboard is the bundled one in `evvp-backend/web/`**, served by the backend at http://127.0.0.1:8000/ with no build step.
It implements every page the project report requires (Overview, Findings, Finding detail with timeline/lead time/risk breakdown/ATT&CK/analyst
workflow, Zero-Days, CVEs, Trending, Threat Landscape, Source Manager, Audit) and is covered by the real-browser tests in
`evvp-backend/scripts/demo.py --browser`. **No required functionality depends on this React app.**

This React app is an earlier prototype of the same dashboard. It type-checks, and the backend keeps the older evidence-level endpoints
(`/api/feed/*`, `/api/search`, `/api/evidence/*`, `/api/verified`, `/api/analyst`) plus a few compatibility fields so it can talk to the API,
but it has **not been built or run** in any verification (the build environment could not install npm packages), its Source Manager page
does not know the newer fields (field mapping for JSON/API sources), and it is not maintained as part of the release.

To try it anyway: `cd evvp-frontend && npm install && npm run dev` (http://localhost:5173, CORS for that origin is allowed by default).
