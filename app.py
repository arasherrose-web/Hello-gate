import hashlib
import hmac
import json
import os
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

from flask import Flask, make_response, redirect, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Part 1: the gate. Cloudflare Turnstile in front of "Hello, World!".
# The widget runs in the visitor's browser and hands the app a token; the app
# checks the token with Cloudflare using the secret key, and only then issues
# the HMAC-signed pass cookie. The site key is public (it appears in the
# page); the secret key lives in the TURNSTILE_SECRET_KEY env var on Render,
# never in this repo. The pass-cookie secret lives in GATE_SECRET likewise.
# ---------------------------------------------------------------------------
SECRET = os.environ.get("GATE_SECRET", "dev-only-toy-secret").encode()
TURNSTILE_SITE_KEY = os.environ.get(
    "TURNSTILE_SITE_KEY", "0x4AAAAAAF9hluOYuWIILAEa"
)
TURNSTILE_SECRET = os.environ.get("TURNSTILE_SECRET_KEY", "")


def sign(msg: str) -> str:
    return hmac.new(SECRET, msg.encode(), hashlib.sha256).hexdigest()[:24]


PASS_TOKEN = sign("passed")


def turnstile_check(token: str, remote_ip: str) -> dict:
    """Ask Cloudflare whether the browser's token is a real pass. Returns
    the siteverify verdict plus Cloudflare's error codes, so every attempt
    can be logged with its reason. Fail closed: no secret configured, no
    token, a network error, or a 'no' from Cloudflare all mean the visitor
    stays outside."""
    if not token:
        return {"success": False, "error_codes": ["missing-input-response"]}
    if not TURNSTILE_SECRET:
        return {"success": False, "error_codes": ["secret-not-configured"]}
    data = urllib.parse.urlencode(
        {"secret": TURNSTILE_SECRET, "response": token, "remoteip": remote_ip}
    ).encode()
    req = urllib.request.Request(
        "https://challenges.cloudflare.com/turnstile/v0/siteverify", data=data
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
    except (urllib.error.URLError, ValueError, TimeoutError):
        return {"success": False, "error_codes": ["network-error"]}
    return {
        "success": result.get("success", False) is True,
        "error_codes": result.get("error-codes", []),
    }

# ---------------------------------------------------------------------------
# Part 2: the honeypot. Deliberately weak-looking bait paths that log every
# knock and serve fake secrets containing canary tripwires.
#
# The tripwire values come from ENV VARS set on Render at deploy time — they
# must NEVER be written into this repo, because the repo is public and a
# tripwire only works if the only people who touch it are intruders.
# Dev defaults below are AWS's own publicly documented example credentials,
# inert by design, so the app still runs locally without the real tokens.
# ---------------------------------------------------------------------------
CANARY_AWS_KEY_ID = os.environ.get("CANARY_AWS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
CANARY_AWS_SECRET = os.environ.get(
    "CANARY_AWS_SECRET", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)
CANARY_WEB_URL = os.environ.get("CANARY_WEB_URL", "http://example.invalid/canary")
CANARY_DNS_HOST = os.environ.get("CANARY_DNS_HOST", "placeholder.example.invalid")

# Fake-but-plausible filler. None of these are real credentials for anything;
# they exist so the bait files look lived-in.
FAKE_DB_PASSWORD = "r0se-garden-2026!fall"
FAKE_REDIS_PASSWORD = "cache-me-if-you-can-88"
FAKE_APP_KEY = "base64:7f3a9c2e1b4d6a8f0c5e7b9d2a4f6c8e1b3d5a7f9c0e2b4d6a8f1c3e5b7d9"

LOGIN_FORM = """<!doctype html>
<html><head><title>Sign in</title></head>
<body style="font-family: sans-serif; max-width: 24em; margin: 4em auto; padding: 0 1em;">
<h1>Sign in</h1>
{error}
<form method="post">
<p><label>Username<br><input name="username" autocomplete="off"></label></p>
<p><label>Password<br><input name="password" type="password"></label></p>
<p><button type="submit">Log in</button></p>
</form>
</body></html>"""


def log_hit(kind, extra=None):
    """One structured line per knock, so Render's logs are the experiment's
    notebook: who came, what they asked for, what they tried."""
    forwarded = request.headers.get("X-Forwarded-For", "") or ""
    ip = forwarded.split(",")[0].strip() or (request.remote_addr or "-")
    line = {
        "t": datetime.now(timezone.utc).isoformat(),
        "ip": ip,
        "kind": kind,
        "method": request.method,
        "path": request.path,
        "ua": request.headers.get("User-Agent", "-")[:160],
    }
    if extra:
        line.update(extra)
    print("HONEYPOT " + json.dumps(line), flush=True)


@app.errorhandler(404)
def not_found(e):
    # Every miss is logged too: the l9scan-style probe battery shows up here.
    log_hit("probe_404")
    return "Not found", 404


@app.route("/robots.txt")
def robots():
    # Polite crawlers obey the first line and stay out. Impolite scanners read
    # the rest of the list as a treasure map — which is exactly the point.
    body = (
        "User-agent: *\n"
        "Disallow: /\n"
        "Disallow: /.env\n"
        "Disallow: /.git/\n"
        "Disallow: /admin\n"
        "Disallow: /backup.zip\n"
        "Disallow: /config.json\n"
    )
    return body, 200, {"Content-Type": "text/plain"}


@app.route("/")
def index():
    # The WordPress user-enumeration probe l9scan used: answer it with fake
    # users instead of the gate.
    if "rest_route" in request.args:
        log_hit("wp_user_enum")
        users = [
            {"id": 1, "name": "admin", "slug": "admin"},
            {"id": 2, "name": "rose", "slug": "rose"},
            {"id": 3, "name": "deploy-bot", "slug": "deploy-bot"},
        ]
        return json.dumps(users), 200, {"Content-Type": "application/json"}
    if hmac.compare_digest(request.cookies.get("gate_pass", ""), PASS_TOKEN):
        log_hit("gate_pass")
        return "Hello, World!"
    log_hit("gate_view")
    html = f"""<!doctype html>
<html><head><title>A tiny gate</title>
<script src="https://challenges.cloudflare.com/turnstile/v0/api.js" async defer></script>
</head>
<body style="font-family: sans-serif; max-width: 32em; margin: 3em auto; padding: 0 1em;">
<h1>One quick check</h1>
<p>The page behind this gate is just a toy, and the gate is an experiment:
it keeps the endless robot traffic out and lets people through.</p>
<form method="post" action="/verify">
<div class="cf-turnstile" data-sitekey="{TURNSTILE_SITE_KEY}"></div>
<button type="submit">Let me in</button>
</form>
</body></html>"""
    return make_response(html)


@app.route("/verify", methods=["POST"])
def verify():
    token = request.form.get("cf-turnstile-response", "")
    forwarded = request.headers.get("X-Forwarded-For", "") or ""
    remote_ip = forwarded.split(",")[0].strip() or (request.remote_addr or "")
    verdict = turnstile_check(token, remote_ip)
    log_hit(
        "gate_verify",
        {
            "success": verdict["success"],
            "token_present": bool(token),
            "error_codes": verdict["error_codes"],
        },
    )
    if not verdict["success"]:
        return redirect("/")
    resp = make_response(redirect("/"))
    resp.set_cookie("gate_pass", PASS_TOKEN, max_age=3600, httponly=True)
    return resp


# --- Bait 1: the secrets file. This is the path every scanner tries first. --
@app.route("/.env")
@app.route("/.env.local")
@app.route("/.env.production")
def fake_env():
    log_hit("bait_env")
    body = f"""APP_ENV=production
APP_DEBUG=false
APP_KEY={FAKE_APP_KEY}
DB_HOST=db.internal.example
DB_DATABASE=rose_prod
DB_USERNAME=rose_admin
DB_PASSWORD={FAKE_DB_PASSWORD}
AWS_ACCESS_KEY_ID={CANARY_AWS_KEY_ID}
AWS_SECRET_ACCESS_KEY={CANARY_AWS_SECRET}
AWS_DEFAULT_REGION=us-east-2
REDIS_HOST={CANARY_DNS_HOST}
REDIS_PASSWORD={FAKE_REDIS_PASSWORD}
MONITORING_WEBHOOK={CANARY_WEB_URL}
"""
    return body, 200, {"Content-Type": "text/plain"}


# --- Bait 2: the source-history leak. The DNS tripwire is the git remote: ---
# anyone who tries to fetch from it resolves the hostname, and that fires.
@app.route("/.git/config")
def fake_git_config():
    log_hit("bait_git_config")
    body = f"""[core]
\trepositoryformatversion = 0
\tfilemode = true
\tbare = false
[user]
\tname = deploy-bot
\temail = deploy@internal.example
[remote "origin"]
\turl = https://{CANARY_DNS_HOST}/rose/website.git
\tfetch = +refs/heads/*:refs/remotes/origin/*
"""
    return body, 200, {"Content-Type": "text/plain"}


@app.route("/.git/HEAD")
def fake_git_head():
    log_hit("bait_git_head")
    return "ref: refs/heads/main\n", 200, {"Content-Type": "text/plain"}


@app.route("/.vscode/sftp.json")
def fake_sftp():
    log_hit("bait_sftp")
    body = json.dumps(
        {
            "name": "prod",
            "host": CANARY_DNS_HOST,
            "protocol": "sftp",
            "port": 22,
            "username": "deploy",
            "password": FAKE_DB_PASSWORD,
            "remotePath": "/var/www/rose",
        },
        indent=2,
    )
    return body, 200, {"Content-Type": "application/json"}


# --- Bait 3: config and debug endpoints. ------------------------------------
@app.route("/config.json")
def fake_config():
    log_hit("bait_config")
    body = json.dumps(
        {
            "app": "rose",
            "env": "production",
            "aws": {
                "access_key_id": CANARY_AWS_KEY_ID,
                "secret_access_key": CANARY_AWS_SECRET,
                "region": "us-east-2",
            },
            "database": {
                "host": "db.internal.example",
                "user": "rose_admin",
                "password": FAKE_DB_PASSWORD,
            },
            "monitoring_webhook": CANARY_WEB_URL,
        },
        indent=2,
    )
    return body, 200, {"Content-Type": "application/json"}


@app.route("/actuator/env")
def fake_actuator():
    log_hit("bait_actuator")
    body = json.dumps(
        {
            "propertySources": [
                {
                    "name": "applicationConfig",
                    "properties": {
                        "aws.accessKey": {"value": CANARY_AWS_KEY_ID},
                        "aws.secretKey": {"value": CANARY_AWS_SECRET},
                        "spring.datasource.password": {"value": FAKE_DB_PASSWORD},
                        "monitoring.webhook": {"value": CANARY_WEB_URL},
                    },
                }
            ]
        },
        indent=2,
    )
    return body, 200, {"Content-Type": "application/json"}


@app.route("/server-status")
def fake_server_status():
    log_hit("bait_server_status")
    return (
        "Apache Server Status for localhost\n\n"
        "Server Version: Apache/2.4.52 (Ubuntu)\n"
        "Server MPM: event\n\n"
        "2 requests currently being processed, 8 idle workers\n",
        200,
        {"Content-Type": "text/plain"},
    )


@app.route("/info.php")
@app.route("/phpinfo.php")
def fake_phpinfo():
    log_hit("bait_phpinfo")
    return (
        "<html><head><title>phpinfo()</title></head><body>"
        "<h1>PHP Version 8.1.2</h1>"
        "<table><tr><td>System</td><td>Linux web-01 5.15.0-generic</td></tr>"
        "<tr><td>DOCUMENT_ROOT</td><td>/var/www/rose</td></tr>"
        "<tr><td>Server Admin</td><td>deploy@internal.example</td></tr></table>"
        "</body></html>",
        200,
    )


# --- Bait 4: the fake login. Always fails; the tried passwords are the prize.
@app.route("/admin", methods=["GET", "POST"])
@app.route("/wp-login.php", methods=["GET", "POST"])
@app.route("/wp-admin", methods=["GET", "POST"])
@app.route("/wp-admin/", methods=["GET", "POST"])
@app.route("/login", methods=["GET", "POST"])
@app.route("/administrator/index.php", methods=["GET", "POST"])
def fake_login():
    if request.method == "POST":
        tried = {
            "username": (request.form.get("username") or request.form.get("log") or "")[:64],
            "password": (request.form.get("password") or request.form.get("pwd") or "")[:64],
        }
        log_hit("bait_login_attempt", tried)
        return LOGIN_FORM.format(
            error='<p style="color: #b00;">ERROR: Invalid username or password.</p>'
        )
    log_hit("bait_login_view")
    return LOGIN_FORM.format(error="")


# --- Bait 5: the fake backup. The download is logged; the file carries the --
# web-bug tripwire in a comment, so anyone who reads it closely may fire it.
@app.route("/backup.zip")
@app.route("/backup.sql")
@app.route("/db.sql")
@app.route("/dump.sql")
@app.route("/site-backup.tar.gz")
def fake_backup():
    log_hit("bait_backup_download")
    body = f"""-- MySQL dump of rose_prod, taken 2026-11-10
-- monitoring: {CANARY_WEB_URL}
CREATE TABLE users (id INT, name VARCHAR(64), pass_hash VARCHAR(255));
INSERT INTO users VALUES (1, 'admin', '$2y$10$f4k3h4shf4k3h4shf4k3h4shf4k3h4shf4k3h4shf4k3h4sh');
INSERT INTO users VALUES (2, 'rose', '$2y$10$f4k3h4shf4k3h4shf4k3h4shf4k3h4shf4k3h4shf4k3h4sh');
"""
    resp = make_response(body)
    resp.headers["Content-Type"] = "application/octet-stream"
    resp.headers["Content-Disposition"] = "attachment; filename=backup.sql"
    return resp


# --- Bait 6: the fake API. Logs whatever query the prober sends. -------------
@app.route("/graphql", methods=["GET", "POST"])
@app.route("/api/graphql", methods=["GET", "POST"])
@app.route("/api/gql", methods=["GET", "POST"])
@app.route("/api", methods=["GET", "POST"])
def fake_graphql():
    log_hit("bait_api", {"body": request.get_data(as_text=True)[:500]})
    return (
        json.dumps(
            {"data": None, "errors": [{"message": "Cannot query field 'admin' on type 'Query'."}]}
        ),
        200,
        {"Content-Type": "application/json"},
    )
