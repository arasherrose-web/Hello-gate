# hello-gate + honeypot

One toy app for rose.opik.net, running two experiments at once.

## Experiment 1: the gate

The homepage ("/") sits behind Cloudflare Turnstile (free tier, widget
"rose-gate", managed mode): the widget runs quiet checks in the visitor's
browser and only shows a checkbox when doubtful. The app verifies the
browser's token with Cloudflare using the secret key, then issues a cookie
pass good for an hour. The question is: do the bots stop at a real
challenge? People pass once and stay in; scanners never get the page. (The
gate began life as one arithmetic question; Turnstile replaced it on
2026-11-11, the day the repo became deployable.)

## Experiment 2: the honeypot

Every other path the scanners love is deliberately weak-looking. The app
serves fake secrets and logs every knock as one structured `HONEYPOT` line
in Render's logs (time, IP, path, user agent, and whatever was tried):

1. **Fake secrets file** — `/.env` (plus `.env.local`, `.env.production`)
   serves a realistic env file holding the canary AWS keys, the canary DNS
   hostname as the Redis host, and the canary web-bug URL as a webhook.
2. **Fake source history** — `/.git/config` points the git remote at the
   canary DNS hostname (a fetch attempt resolves it and fires the tripwire);
   `/.git/HEAD` and `/.vscode/sftp.json` round out the leak.
3. **Fake config/debug endpoints** — `/config.json`, `/actuator/env`,
   `/server-status`, `/info.php` serve plausible internals with tripwires.
4. **Fake logins** — `/admin`, `/wp-login.php`, `/login` and friends show a
   sign-in form that always fails and logs every username/password tried.
   The tried passwords are the prize.
5. **Fake backup** — `/backup.zip`, `/db.sql`, `/dump.sql` serve a fake SQL
   dump carrying the web-bug tripwire in a comment.
6. **Fake API** — `/graphql`, `/api/graphql`, `/api` log whatever query
   arrives and answer with a plausible GraphQL error.
7. **The 404 logger** — every other probe is logged too, so the whole
   scanner battery shows up in one place. `robots.txt` lists the bait
   paths as disallowed: polite crawlers stay out, and impolite scanners
   read the list as a treasure map.

## The tripwires (canary tokens)

Three Canarytokens from canarytokens.org (Thinkst, free), all alerting
Asher's Gmail, created 2026-11-11:

- **AWS keys** — fires when anyone validates or uses the fake key pair
  (bots check stolen AWS keys against AWS within minutes, typically).
- **Web bug URL** — fires when the URL is fetched.
- **DNS hostname** — fires when the hostname is resolved.

The token values live ONLY as Render env vars (`CANARY_AWS_KEY_ID`,
`CANARY_AWS_SECRET`, `CANARY_WEB_URL`, `CANARY_DNS_HOST`), set at deploy
time from `~/workspace/honeypot/tokens.json`, which is outside this repo.
They must never be committed: a tripwire only works if the only people who
touch it are intruders. Without the env vars the app serves AWS's own
documented example credentials, which are inert by design.

## Rules of the experiment

- Passive watching only. The app never strikes back, never scans anyone,
  never serves anything harmful. Bait values are inert fakes.
- Total isolation: nothing on this service connects to any real account,
  database, or credential. The toy holds no real data.

## Deploy (once the repo exists)

1. Asher creates public repo `hello-gate` (no README) and adds it to the
   Muse GitHub App's repository selection.
2. Muse pushes these files, sets env vars on the Render starter service
   (`GATE_SECRET` + the four `CANARY_*` vars), repoints the service at
   the repo, and deploys.
3. Watch: canary alerts arrive by email; `HONEYPOT` lines in Render's
   Logs tab show every knock and every tried password.
