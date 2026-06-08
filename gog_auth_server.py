#!/usr/bin/env python3
"""
gog_auth_server.py — Web UI for gog two-step remote OAuth over VPN.

Flow:
  1. Open http://<box-vpn-ip>:7080 on iPhone
  2. Tap "Start Auth" — box runs gog --remote --step 1, shows the Google OAuth URL
  3. Tap the link, sign in — Safari lands on a failed 127.0.0.1 page
  4. Copy the full URL from Safari's address bar, paste it, tap Submit
  5. Server runs gog --remote --step 2 with the redirect URL

Usage:
    python3 gog_auth_server.py --account me@example.com
    python3 gog_auth_server.py --account me@example.com --services gmail,calendar --port 7080 --ttl 540
"""

# /// script
# requires-python = ">=3.11"
# ///

import argparse
import json
import os
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

DEFAULT_PORT     = 7080
DEFAULT_ACCOUNT  = ""
DEFAULT_SERVICES = "all-user"
DEFAULT_TTL      = 540

state = {
    "phase":      "idle",
    "auth_url":   None,
    "expires_at": None,
    "log":        [],
    "result":     None,
    "verify":     None,
}
_lock = threading.Lock()


def log(cmd: str, rc: int, stdout: str, stderr: str, t0: float):
    elapsed = time.time() - t0
    ts = time.strftime("[%H:%M:%S]")
    out = f"{ts} gog {cmd}  exit={rc}  {elapsed:.2f}s"
    if stdout.strip():
        first_line = stdout.strip().split("\n")[0]
        out += f"  out={first_line[:120]}"
    if stderr.strip():
        first_line = stderr.strip().split("\n")[0]
        out += f"  err={first_line[:120]}"
    print(out, flush=True)


def run_step1(account: str, services: str):
    """Returns (auth_url, error_msg, log_lines)."""
    cmd = [
        "gog", "auth", "add", account,
        "--services", services,
        "--remote", "--step", "1",
    ]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        log("step1", -1, "", "timeout", t0)
        return (None, "gog step 1 timed out after 30s", [])
    except FileNotFoundError:
        log("step1", -1, "", "command not found", t0)
        return (None, "gog not found — is gogcli installed?", [])

    log("step1", r.returncode, r.stdout, r.stderr, t0)
    log_lines = (r.stdout + r.stderr).strip().splitlines()

    if r.returncode != 0:
        err = r.stderr.strip() or r.stdout.strip() or f"step 1 exited with code {r.returncode}"
        return (None, err, log_lines)

    auth_url = None
    for line in r.stdout.strip().split("\n"):
        if line.startswith("auth_url\t"):
            auth_url = line.split("\t", 1)[1].strip()
            break

    if not auth_url:
        return (None, "No auth_url in gog step 1 output. Check log.", log_lines)
    return (auth_url, None, log_lines)


def run_step2(account: str, services: str, redirect_url: str):
    """Returns (ok, result_info, error_msg, log_lines)."""
    cmd = [
        "gog", "auth", "add", account,
        "--services", services,
        "--remote", "--step", "2",
        "--auth-url", redirect_url,
    ]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except subprocess.TimeoutExpired:
        log("step2", -1, "", "timeout", t0)
        return (False, None, "gog step 2 timed out after 30s", [])
    except FileNotFoundError:
        log("step2", -1, "", "command not found", t0)
        return (False, None, "gog not found — is gogcli installed?", [])

    log("step2", r.returncode, r.stdout, r.stderr, t0)
    log_lines = (r.stdout + r.stderr).strip().splitlines()

    if r.returncode != 0:
        err = r.stderr.strip() or r.stdout.strip() or f"step 2 exited with code {r.returncode}"
        return (False, None, err, log_lines)

    info = {}
    for line in r.stdout.strip().split("\n"):
        if "\t" in line:
            k, v = line.split("\t", 1)
            info[k.strip()] = v.strip()

    return (True, info, None, log_lines)


def run_verify(account: str):
    """Returns (ok, result_or_error, log_lines).  On success, the result dict
    includes a ``status`` key populated from ``gog status`` output."""
    cmd = ["gog", "auth", "list", "--check", "--json", "--no-input", "--account", account]
    t0 = time.time()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
    except subprocess.TimeoutExpired:
        log("verify", -1, "", "timeout", t0)
        return (False, "Verification timed out", [])
    except FileNotFoundError:
        log("verify", -1, "", "command not found", t0)
        return (False, "gog not found", [])

    log("verify", r.returncode, r.stdout, r.stderr, t0)
    log_lines = (r.stdout + r.stderr).strip().splitlines()

    if r.returncode != 0:
        return (False, r.stderr.strip() or r.stdout.strip() or "Verification failed", log_lines)

    try:
        data = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        return (False, "Could not parse verification output", log_lines)

    # Also run gog status for diagnostic info
    status_lines = []
    try:
        sr = subprocess.run(
            ["gog", "status"],
            capture_output=True, text=True, timeout=10,
        )
        log("status", sr.returncode, sr.stdout, sr.stderr, t0)
        if sr.returncode == 0:
            data["status"] = sr.stdout.strip()
            status_lines = sr.stdout.strip().splitlines()
        else:
            err = sr.stderr.strip() or sr.stdout.strip()
            data["status"] = f"error: {err}" if err else "status command failed"
            if err:
                status_lines = [f"status error: {err}"]
        log_lines.extend(status_lines)
    except subprocess.TimeoutExpired:
        log("status", -1, "", "timeout", t0)
        data["status"] = "timeout"
    except FileNotFoundError:
        log("status", -1, "", "command not found", t0)

    return (True, data, log_lines)


HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>gog Auth</title>
<style>
:root{--bg:#0f1117;--card:#1a1d27;--bdr:#2a2d3a;--tx:#e2e4f0;--mt:#7b7f96;
  --bl:#4f8ef7;--gr:#3ecf8e;--rd:#f75f5f}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--tx);
  font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
  min-height:100vh;min-height:100dvh;display:flex;align-items:center;
  justify-content:center;padding:max(16px, env(safe-area-inset-top)) max(16px, env(safe-area-inset-right))
    max(16px, env(safe-area-inset-bottom)) max(16px, env(safe-area-inset-left));
  overscroll-behavior:none;-webkit-overflow-scrolling:touch}
.card{background:var(--card);border:1px solid var(--bdr);border-radius:16px;
  padding:28px 22px;width:100%;max-width:500px}
h1{font-size:1.35rem;font-weight:700;margin-bottom:3px}
.sub{color:var(--mt);font-size:.92rem;margin-bottom:20px}
.badge{display:inline-block;padding:4px 12px;border-radius:99px;font-size:.88rem;
  font-weight:600;margin-bottom:16px}
.idle{background:#2a2d3a;color:var(--mt)}
.need_redirect{background:#1e2d2a;color:var(--gr)}
.submitting{background:#1e2a40;color:var(--bl)}
.done{background:#1a2e24;color:var(--gr)}
.error{background:#2e1a1a;color:var(--rd)}
.btn{width:100%;padding:15px;border:none;border-radius:10px;font-size:1.05rem;
  font-weight:600;cursor:pointer;transition:opacity .15s;
  touch-action:manipulation;-webkit-tap-highlight-color:transparent;
  user-select:none;-webkit-user-select:none}
.btn:active{opacity:.7}
.btn-sm{padding:14px;font-size:1rem}
.bp{background:var(--bl);color:#fff}
.bg{background:var(--gr);color:#000}
.bm{background:var(--bdr);color:var(--mt)}
.url-box{background:#11131e;border:1px solid var(--bdr);border-radius:10px;
  padding:14px;margin:14px 0;word-break:break-all;font-size:.94rem;line-height:1.6}
.url-box a{color:var(--bl);text-decoration:none;font-size:.96rem}
.step{font-size:.96rem;color:var(--mt);margin-top:16px;margin-bottom:6px;line-height:1.5}
.step b{color:var(--tx)}
textarea{width:100%;padding:12px 14px;border-radius:9px;border:1px solid var(--bdr);
  background:#11131e;color:var(--tx);font-size:16px;margin:6px 0 12px;outline:none;
  display:block;resize:vertical;min-height:80px;font-family:monospace;line-height:1.5}
textarea:focus{border-color:var(--bl)}
.timer{font-size:.92rem;color:var(--mt);margin-bottom:12px;font-variant-numeric:tabular-nums}
.timer.warn strong{color:var(--rd)}
.info-row{font-size:.88rem;color:var(--mt);margin-top:6px}
.info-row strong{color:var(--tx)}
.result{margin-top:14px;padding:14px 16px;border-radius:10px;font-size:1rem;line-height:1.5}
.result.done{background:#1a2e24;color:var(--gr);border:1px solid #2a4a3a}
.result.error{background:#2e1a1a;color:var(--rd);border:1px solid #4a2a2a}
.log-toggle{background:none;border:none;color:var(--mt);font-size:.88rem;
  cursor:pointer;text-decoration:underline;padding:8px 0;display:block;margin-top:16px;
  touch-action:manipulation;min-height:44px}
.log{margin-top:8px;background:#0a0c13;border:1px solid var(--bdr);border-radius:8px;
  padding:10px 12px;font-family:monospace;font-size:.78rem;color:var(--mt);
  max-height:140px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;display:none}
.spin{display:inline-block;width:13px;height:13px;border:2px solid #2a2d3a;
  border-top-color:var(--bl);border-radius:50%;animation:sp .7s linear infinite;
  vertical-align:middle;margin-right:5px}
@keyframes sp{to{transform:rotate(360deg)}}
.panel{display:none}
.panel.active{display:block}
</style>
</head>
<body>
<div class="card">
  <h1>&#128273; gog Auth</h1>
  <p class="sub" id="sub">&hellip;</p>
  <span id="badge" class="badge idle">idle</span>

  <div id="panel-idle" class="panel active">
    <button class="btn bp" onclick="doStep1()">Start authentication</button>
  </div>

  <div id="panel-redirect" class="panel">
    <div id="redirect-active">
      <p class="step"><b>1</b> &mdash; Open Google sign-in:</p>
      <div class="url-box">
        <a id="gog-link" href="#" target="_blank">&#128279;&nbsp;Tap to open Google sign-in &nearr;</a>
      </div>
      <p class="timer" id="timer"></p>
      <p class="step"><b>2</b> &mdash; Sign in. Safari will land on a page that fails to load&nbsp;(<code>127.0.0.1&hellip;</code>).</p>
      <p class="step"><b>3</b> &mdash; Copy the full URL from the address bar and paste it below:</p>
      <textarea id="ru" placeholder="http://127.0.0.1:&hellip;/oauth2/callback?state=&hellip;&code=&hellip;"
        autocomplete="off" autocorrect="off" spellcheck="false"></textarea>
      <button class="btn bg" id="btn-submit" onclick="doStep2()">Submit &rarr;</button>
    </div>
    <div id="redirect-expired" style="display:none">
      <div class="result error">&#9200;&nbsp;Authentication link expired</div>
      <button class="btn bp btn-sm" style="margin-top:14px" onclick="doStep1()">Restart step 1</button>
    </div>
  </div>

  <div id="panel-submitting" class="panel">
    <button class="btn bm"><span class="spin"></span>Completing auth&hellip;</button>
  </div>

  <div id="panel-done" class="panel">
    <div class="result done" id="result-done"></div>
    <div id="info-done"></div>
    <div id="verify-done" style="margin-top:14px;padding:14px 16px;border-radius:10px;
      background:#11131e;border:1px solid var(--bdr);font-size:.85rem;line-height:1.6;display:none"></div>
    <button class="btn bp btn-sm" style="margin-top:14px" onclick="doStep1()">Auth again</button>
    <button class="btn bm btn-sm" style="margin-top:6px" onclick="doVerify()">Check token</button>
  </div>

  <div id="panel-error" class="panel">
    <div class="result error" id="result-error"></div>
    <button class="btn bp btn-sm" style="margin-top:14px" onclick="doStep1()">Try again</button>
  </div>

  <button class="log-toggle" onclick="toggleLog()">Show raw log</button>
  <div class="log" id="log"></div>
</div>

<script>
var panels={idle:'panel-idle',need_redirect:'panel-redirect',
  submitting:'panel-submitting',done:'panel-done',error:'panel-error'};

var label={idle:'idle',need_redirect:'waiting for redirect',
  submitting:'processing\u2026',done:'authenticated \u2713',error:'error'};

var timerId=null;

function show(p){
  for(var k in panels) document.getElementById(panels[k]).classList.remove('active');
  var el=document.getElementById(panels[p]);
  if(el) el.classList.add('active');
}

function render(s){
  document.getElementById('sub').textContent =
    'Account: '+(s.account||'\u2014')+' \u00b7 Services: '+(s.services||'\u2014');

  var badge=document.getElementById('badge');
  badge.className='badge '+s.phase;
  badge.textContent=label[s.phase]||s.phase;

  show(s.phase);

  if(s.log&&s.log.length) document.getElementById('log').textContent=s.log.join('\\n');

  if(s.phase==='need_redirect'){
    document.getElementById('gog-link').href=s.auth_url||'#';
    startTimer(s.expires_at);
  }
  if(s.phase==='done'){
    clearTimer();
    document.getElementById('result-done').textContent='\u2713\u00a0Authentication successful';
    var info='';
    if(s.info){
      if(s.info.email) info+='<div class="info-row"><strong>Email:</strong> '+s.info.email+'</div>';
      if(s.info.client) info+='<div class="info-row"><strong>Client:</strong> '+s.info.client+'</div>';
      if(s.info.services) info+='<div class="info-row"><strong>Services:</strong> '+s.info.services+'</div>';
    }
    document.getElementById('info-done').innerHTML=info;

    var vd=document.getElementById('verify-done');
    if(s.verify){
      vd.style.display='block';
      if(s.verify.error){
        vd.innerHTML='<span style="color:var(--rd)">\u2717\u00a0Token check failed: '+s.verify.error+'</span>';
      } else {
        var lines=[];
        if(s.verify.email) lines.push('<div class="info-row"><strong>Email:</strong> '+s.verify.email+'</div>');
        if(s.verify.client) lines.push('<div class="info-row"><strong>Client:</strong> '+s.verify.client+'</div>');
        if(s.verify.services) lines.push('<div class="info-row"><strong>Services:</strong> '+s.verify.services+'</div>');
        if(s.verify.expires_in) lines.push('<div class="info-row"><strong>Expires:</strong> '+s.verify.expires_in+'s</div>');
        vd.innerHTML=(lines.length?'<div style="color:var(--gr);font-weight:600;margin-bottom:4px">\u2713\u00a0Token check OK</div>':'')+lines.join('');
        if(s.verify.status){
          var st=document.createElement('div');
          st.className='info-row';
          st.style.cssText='margin-top:6px;white-space:pre-wrap;font-family:monospace;font-size:.78rem';
          st.textContent=s.verify.status;
          vd.appendChild(st);
        }
      }
    } else {
      vd.style.display='none';
    }
  }
  if(s.phase==='error'){
    clearTimer();
    document.getElementById('result-error').textContent='\u2717\u00a0'+s.result;
  }
}

function clearTimer(){ if(timerId){clearInterval(timerId);timerId=null;} }

function startTimer(exp){
  clearTimer();
  if(!exp) return;
  var active=document.getElementById('redirect-active');
  var expired=document.getElementById('redirect-expired');
  var el=document.getElementById('timer');
  active.style.display='block';
  expired.style.display='none';

  function tick(){
    var left=Math.max(0,Math.ceil(exp-Date.now()/1000));
    var m=Math.floor(left/60), s=left%60;
    el.textContent='Link expires in: '+(m?m+'m ':'')+s+'s';
    el.className='timer'+(left<=60?' warn':'');
    if(left<=0){
      clearTimer();
      active.style.display='none';
      expired.style.display='block';
    }
  }
  tick();
  timerId=setInterval(tick,1000);
}

async function doStep1(){
  show('submitting');
  clearTimer();
  var el=document.getElementById('ru');
  if(el) el.value='';
  try{
    var r=await fetch('/step1',{method:'POST'});
    var s=await r.json();
    render(s);
  }catch(e){render({phase:'error',result:'Network error \u2014 check VPN connection',log:[]});}
}

async function doStep2(){
  var el=document.getElementById('ru');
  var url=(el?el.value:'').trim();
  if(!url){alert('Paste the redirect URL first.');return;}
  if(!/^https?:\\/\\//i.test(url)){url='http://'+url;el.value=url;}
  show('submitting');
  try{
    var r=await fetch('/step2',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    var s=await r.json();
    render(s);
  }catch(e){render({phase:'error',result:'Network error \u2014 check VPN connection',log:[]});}
}

async function doVerify(){
  show('submitting');
  try{
    var r=await fetch('/verify',{method:'POST'});
    var s=await r.json();
    render(s);
  }catch(e){render({phase:'error',result:'Network error \u2014 check VPN connection',log:[]});}
}

function toggleLog(){
  var el=document.getElementById('log');
  el.style.display=el.style.display==='none'?'block':'none';
}

fetch('/state').then(function(r){return r.json();}).then(render);
</script>
</body>
</html>"""


CORS = {
    "Access-Control-Allow-Origin":  "*",
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *_): pass

    def _send(self, body: bytes, ct: str, status=200):
        self.send_response(status)
        self.send_header("Content-Type", ct)
        self.send_header("Content-Length", str(len(body)))
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, data, status=200):
        self._send(json.dumps(data).encode(), "application/json", status)

    def _body(self) -> dict:
        n = int(self.headers.get("Content-Length", 0))
        try:
            return json.loads(self.rfile.read(n))
        except Exception:
            return {}

    def _snapshot(self):
        with _lock:
            return {k: v for k, v in state.items()}

    def do_OPTIONS(self):
        self.send_response(204)
        for k, v in CORS.items():
            self.send_header(k, v)
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path in ("/", "/index.html"):
            self._send(HTML.encode(), "text/html; charset=utf-8")
        elif path == "/state":
            snap = self._snapshot()
            snap["account"]  = self.server.account
            snap["services"] = self.server.services
            self._json(snap)
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/step1":
            with _lock:
                phase = state["phase"]
            if phase == "submitting":
                self._json(self._error_snap("Auth already in progress"))
                return

            account = self.server.account
            services = self.server.services
            ttl = self.server.ttl

            auth_url, err, logs = run_step1(account, services)

            with _lock:
                state["log"] = logs
                if err:
                    state["phase"] = "error"
                    state["result"] = err
                    state["auth_url"] = None
                    state["expires_at"] = None
                else:
                    state["phase"] = "need_redirect"
                    state["auth_url"] = auth_url
                    state["expires_at"] = time.time() + ttl
                    state["result"] = None
                    state["verify"] = None
            self._json(self._snapshot())

        elif path == "/step2":
            body = self._body()
            redirect_url = body.get("url", "").strip()

            if redirect_url and "://" not in redirect_url:
                redirect_url = "http://" + redirect_url

            with _lock:
                phase = state["phase"]
                expires = state["expires_at"]

            if phase != "need_redirect":
                self._json(self._error_snap("No authentication link active — run step 1 first"))
                return

            if expires and time.time() > expires:
                with _lock:
                    state["phase"] = "error"
                    state["result"] = "Authentication link has expired. Restart step 1."
                self._json(self._snapshot())
                return

            if not redirect_url:
                self._json(self._error_snap("No URL provided"))
                return

            if "code=" not in redirect_url:
                self._json(self._error_snap(
                    "Doesn't look like an OAuth callback (no code= parameter)"))
                return

            if "state=" not in redirect_url:
                self._json(self._error_snap(
                    "Redirect URL must include state= parameter for --remote auth"))
                return

            account = self.server.account
            services = self.server.services

            ok, info, err, logs = run_step2(account, services, redirect_url)

            if ok:
                v_ok, v_data, v_logs = run_verify(account)
                logs = logs + v_logs
                with _lock:
                    state["log"] = logs
                    state["phase"] = "done"
                    state["result"] = "Authentication successful"
                    state["auth_url"] = None
                    state["expires_at"] = None
                    state["verify"] = v_data if v_ok else {"error": v_data}
                snap = self._snapshot()
                snap["info"] = info
            else:
                with _lock:
                    state["log"] = logs
                    state["phase"] = "error"
                    state["result"] = err
                    state["auth_url"] = None
                    state["expires_at"] = None
                    state["verify"] = None
                snap = self._snapshot()
            self._json(snap)

        elif path == "/verify":
            account = self.server.account
            v_ok, v_data, v_logs = run_verify(account)
            with _lock:
                state["log"] = state["log"] + v_logs
                state["verify"] = v_data if v_ok else {"error": v_data}
            self._json(self._snapshot())

        else:
            self.send_error(404)

    def _error_snap(self, msg):
        return {"phase": "error", "result": msg, "auth_url": None,
                "expires_at": None, "log": [], "verify": None}


def main():
    ap = argparse.ArgumentParser(description="gog OAuth helper \u2014 two-step remote auth via iPhone over VPN")
    ap.add_argument("--port",     type=int, default=DEFAULT_PORT)
    ap.add_argument("--host",     type=str, default="0.0.0.0")
    ap.add_argument("--account",  type=str, default=DEFAULT_ACCOUNT,
                    help="Account passed to: gog auth add <ACCOUNT>")
    ap.add_argument("--services", type=str, default=DEFAULT_SERVICES,
                    help="Passed to --services flag (default: all-user)")
    ap.add_argument("--ttl",      type=int, default=DEFAULT_TTL,
                    help="Authentication link lifetime in seconds (default: 540)")
    args = ap.parse_args()

    if not args.account:
        print("\n  \u26a0  Specify --account me@example.com  (or set DEFAULT_ACCOUNT in the script)\n")
        ap.print_help()
        sys.exit(1)

    required_env = ["GOG_ACCOUNT", "GOG_KEYRING_BACKEND", "GOG_KEYRING_PASSWORD"]
    missing = [v for v in required_env if v not in os.environ]
    if missing:
        print(f"\n  \u26a0  Missing environment variables: {', '.join(missing)}")
        print(   "     Set them before running the server.\n")
        sys.exit(1)

    try:
        import socket
        ips = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
               if not ip.startswith("127.")]
    except Exception:
        ips = []

    print(f"\n  gog Auth \u2014 port {args.port}  ttl={args.ttl}s")
    print(f"  Account: {args.account}  Services: {args.services}\n")
    for ip in ips:
        print(f"  \u2192 http://{ip}:{args.port}   \u2190 open on iPhone (VPN on)")
    print(f"  \u2192 http://localhost:{args.port}\n")

    srv = HTTPServer((args.host, args.port), Handler)
    srv.port     = args.port
    srv.account  = args.account
    srv.services = args.services
    srv.ttl      = args.ttl
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
