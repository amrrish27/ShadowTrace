# Screenshots

This directory is intentionally empty in the delivered archive.

Screenshots are script-generated from the running UI, which needs a browser. The build
environment for this delivery had no browser binaries (see `docs/known-issues.md` §A5–A6), so
producing them would have meant shipping images that were not captured from this code — which
the evidence rules in this repository forbid.

Reproduce them with:

```bash
# terminal 1
make lab
# terminal 2
ST_ENV=test ST_DATABASE_PATH=/tmp/st_demo.db ST_PRIVATE_ALLOWLIST=127.0.0.1:8099 \
  ST_BOOTSTRAP_ADMIN_EMAIL=admin@example.test \
  ST_BOOTSTRAP_ADMIN_PASSWORD='Bootstrap-Admin-Pass-9!' \
  python3 -m uvicorn app.main:app --app-dir backend --host 0.0.0.0 --port 8000

# terminal 3
make demo-seed
cd frontend && npx playwright install chromium
npx playwright test --project=chromium          # journeys
npx playwright screenshot --viewport-size=1440,900 http://127.0.0.1:8000 \
  ../docs/screenshots/01-sign-in.png
```

The two Playwright journeys in `frontend/e2e/smoke.spec.ts` cover sign-in → dashboard and
scan → findings → export; they can be extended with `page.screenshot()` to fill this folder.
