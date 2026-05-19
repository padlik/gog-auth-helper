#!/usr/bin/env python3
"""
gog_auth_server.py — Web UI for gog re-authentication over VPN.

Flow:
  1. Open http://<box-vpn-ip>:7080 on iPhone
  2. Tap "Start Auth" — box runs gog --manual and shows the Google OAuth URL
  3. Tap the link, sign in — Safari lands on a failed 127.0.0.1 page
  4. Copy the full URL from Safari's address bar, paste it here, tap Submit

Usage:
    python3 gog_auth_server.py --account me@example.com
    python3 gog_auth_server.py --account me@example.com --services gmail,calendar --port 7080
"""

import argparse
import json
import re
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse

DEFAULT_PORT     = 7080
DEFAULT_ACCOUNT  = ""
DEFAULT_SERVICES = "user"

GOOGLE_URL_RE = re.compile(r"https?://accounts\.google\.[a-z.]+/\S+")

state = {
    "phase":   "idle",
    "gog_url": None,
    "log":     [],
    "result":  None,
    "proc":    None,
}
_lock = threading.Lock()


def auth_worker(account: str, services: str):
    cmd = f"gog auth add {account} --services {services} --manual"
    with _lock:
        state.update(phase="running", gog_url=None, log=[], result=None, proc=None)
    try:
        proc = subprocess.Popen(
            cmd, shell=True,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            text=True, bufsize=1,
        )
        with _lock:
            state["proc"] = proc

        found = False
        for line in proc.stdout:
            line = line.rstrip()
            with _lock:
                state["log"].append(line)
            m = GOOGLE_URL_RE.search(line)
            if m:
                with _lock:
                    state["gog_url"] = m.group(0)
                    state["phase"]   = "need_redirect"
                found = True
                break

        if not found:
            proc.wait()
            with _lock:
                state["phase"]  = "error"
                state["result"] = "No Google OAuth URL found in gog output. Check log."
            return

        while True:
            with _lock:
                phase = state["phase"]
            if phase == "submitting":
                break
            if proc.poll() is not None:
                with _lock:
                    state["phase"]  = "error"
                    state["result"] = "gog process exited before redirect was received."
                return
            time.sleep(0.25)

        rest = proc.stdout.read()
        proc.wait()
        with _lock:
            for l in rest.splitlines():
                state["log"].append(l)
            if proc.returncode == 0:
                state["phase"]  = "done"
                state["result"] = "Authentication successful \u2713"
            else:
                state["phase"]  = "error"
                state["result"] = f"gog exited with code {proc.returncode}. Check log."

    except Exception as exc:
        with _lock:
            state["phase"]  = "error"
            state["result"] = str(exc)


def feed_redirect_url(redirect_url: str):
    with _lock:
        proc  = state["proc"]
        phase = state["phase"]
    if phase != "need_redirect" or proc is None:
        return False, "Not waiting for a redirect URL right now."
    try:
        proc.stdin.write(redirect_url + "\n")
        proc.stdin.flush()
        proc.stdin.close()
        with _lock:
            state["phase"] = "submitting"
        return True, "OK"
    except Exception as exc:
        return False, str(exc)


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
  min-height:100vh;display:flex;align-items:center;justify-content:center;padding:16px}
.card{background:var(--card);border:1px solid var(--bdr);border-radius:16px;
  padding:26px 22px;width:100%;max-width:480px}
h1{font-size:1.2rem;font-weight:700;margin-bottom:3px}
.sub{color:var(--mt);font-size:.8rem;margin-bottom:20px}
.badge{display:inline-block;padding:3px 10px;border-radius:99px;font-size:.76rem;
  font-weight:600;margin-bottom:16px}
.idle{background:#2a2d3a;color:var(--mt)}
.running{background:#1e2a40;color:var(--bl)}
.need_redirect{background:#1e2d2a;color:var(--gr)}
.submitting{background:#1e2a40;color:var(--bl)}
.done{background:#1a2e24;color:var(--gr)}
.error{background:#2e1a1a;color:var(--rd)}
.btn{width:100%;padding:14px;border:none;border-radius:10px;font-size:1rem;
  font-weight:600;cursor:pointer;transition:opacity .15s}
.btn:active{opacity:.75}
.bp{background:var(--bl);color:#fff}
.bg{background:var(--gr);color:#000}
.bm{background:var(--bdr);color:var(--mt);cursor:default}
.url-box{background:#11131e;border:1px solid var(--bdr);border-radius:10px;
  padding:14px;margin:12px 0;word-break:break-all;font-size:.8rem;line-height:1.6}
.url-box a{color:var(--bl);text-decoration:none;font-size:.85rem}
.step{font-size:.82rem;color:var(--mt);margin-top:14px;margin-bottom:6px;line-height:1.5}
.step b{color:var(--tx)}
textarea{width:100%;padding:11px 13px;border-radius:9px;border:1px solid var(--bdr);
  background:#11131e;color:var(--tx);font-size:.8rem;margin:6px 0 12px;outline:none;
  display:block;resize:vertical;min-height:72px;font-family:monospace;line-height:1.5}
textarea:focus{border-color:var(--bl)}
.result{margin-top:14px;padding:12px 14px;border-radius:10px;font-size:.88rem;line-height:1.5}
.result.done{background:#1a2e24;color:var(--gr);border:1px solid #2a4a3a}
.result.error{background:#2e1a1a;color:var(--rd);border:1px solid #4a2a2a}
.log-toggle{background:none;border:none;color:var(--mt);font-size:.75rem;
  cursor:pointer;text-decoration:underline;padding:0;display:block;margin-top:16px}
.log{margin-top:8px;background:#0a0c13;border:1px solid var(--bdr);border-radius:8px;
  padding:10px 12px;font-family:monospace;font-size:.72rem;color:var(--mt);
  max-height:140px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;display:none}
.spin{display:inline-block;width:13px;height:13px;border:2px solid #2a2d3a;
  border-top-color:var(--bl);border-radius:50%;animation:sp .7s linear infinite;
  vertical-align:middle;margin-right:5px}
@keyframes sp{to{transform:rotate(360deg)}}
.panel{display:none}
.panel.active{display:block}
.panel-submit{display:block}
</style>
</head>
<body>
<div class="card">
  <h1>&#128273; gog Auth</h1>
  <p class="sub" id="sub">&hellip;</p>
  <span id="badge" class="badge idle">idle</span>

  <div id="panel-idle" class="panel active">
    <button class="btn bp" onclick="startAuth()">Start authentication</button>
  </div>

  <div id="panel-running" class="panel">
    <button class="btn bm"><span class="spin"></span>Launching gog&hellip;</button>
  </div>

  <div id="panel-redirect" class="panel">
    <p class="step"><b>1</b> &mdash; Open Google sign-in:</p>
    <div class="url-box">
      <a id="gog-link" href="#" target="_blank">&#128279;&nbsp;Tap to open Google sign-in &nearr;</a>
    </div>
    <p class="step"><b>2</b> &mdash; Sign in. Safari will land on a page that fails to load&nbsp;(<code>127.0.0.1&hellip;</code>).</p>
    <p class="step"><b>3</b> &mdash; Copy the full URL from the address bar and paste it below:</p>
    <textarea id="ru" placeholder="http://127.0.0.1:&hellip;/?code=&hellip;"
      autocomplete="off" autocorrect="off" spellcheck="false"></textarea>
    <button class="btn bg" id="btn-submit" onclick="submitRedirect()">Submit &rarr;</button>
  </div>

  <div id="panel-submitting" class="panel">
    <button class="btn bm"><span class="spin"></span>Completing auth&hellip;</button>
  </div>

  <div id="panel-done" class="panel">
    <div class="result done" id="result-done"></div>
    <button class="btn bp" style="margin-top:14px" onclick="startAuth()">Auth again</button>
  </div>

  <div id="panel-error" class="panel">
    <div class="result error" id="result-error"></div>
    <button class="btn bp" style="margin-top:14px" onclick="startAuth()">Try again</button>
  </div>

  <button class="log-toggle" onclick="toggleLog()">Show raw log</button>
  <div class="log" id="log"></div>
</div>

<script>
const panels={idle:'panel-idle',running:'panel-running',need_redirect:'panel-redirect',
  submitting:'panel-submitting',done:'panel-done',error:'panel-error'};

const label={idle:'idle',running:'connecting\u2026',need_redirect:'waiting for redirect',
  submitting:'processing\u2026',done:'authenticated \u2713',error:'error'};

function showPanel(phase){
  for(var k in panels) document.getElementById(panels[k]).classList.remove('active');
  var el=document.getElementById(panels[phase]);
  if(el) el.classList.add('active');
}

var _curPhase=null;
function render(s){
  document.getElementById('sub').textContent =
    'Account: '+(s.account||'\u2014')+' \u00b7 Services: '+(s.services||'\u2014');

  var badge=document.getElementById('badge');
  badge.className='badge '+s.phase;
  badge.textContent=label[s.phase]||s.phase;

  if(_curPhase!==s.phase){
    _curPhase=s.phase;
    showPanel(s.phase);
  }

  if(s.phase==='need_redirect'&&s.gog_url){
    document.getElementById('gog-link').href=s.gog_url;
  }
  if(s.phase==='done'){
    document.getElementById('result-done').textContent='\u2713\u00a0'+s.result;
    stopPoll();
  }
  if(s.phase==='error'){
    document.getElementById('result-error').textContent='\u2717\u00a0'+s.result;
    stopPoll();
  }
  if(s.log&&s.log.length) document.getElementById('log').textContent=s.log.join('\\n');
}

async function startAuth(){
  var el=document.getElementById('ru');
  if(el) el.value='';
  await fetch('/start',{method:'POST'});
  startPoll();
}

async function submitRedirect(){
  var el=document.getElementById('ru');
  var url=(el?el.value:'').trim();
  if(!url){alert('Paste the redirect URL first.');return;}
  var r=await fetch('/redirect',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
  var d=await r.json();
  if(!d.ok){alert('Error: '+d.msg);return;}
  showPanel('submitting');
  startPoll();
}

var timer=null,active=false;
function startPoll(){if(!active){active=true;poll();}}
function stopPoll(){active=false;clearTimeout(timer);}
async function poll(){
  if(!active)return;
  try{
    var s=await fetch('/state').then(function(r){return r.json();});
    render(s);
    if(s.phase!=='done'&&s.phase!=='error') timer=setTimeout(poll,800);
  }catch(e){timer=setTimeout(poll,2000);}
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
            with _lock:
                snap = {k: v for k, v in state.items() if k != "proc"}
            snap["account"]  = self.server.account
            snap["services"] = self.server.services
            self._json(snap)
        else:
            self.send_error(404)

    def do_POST(self):
        path = urlparse(self.path).path

        if path == "/start":
            with _lock:
                phase = state["phase"]
            if phase in ("running", "need_redirect", "submitting"):
                self._json({"ok": False, "msg": "Auth already in progress"})
                return
            threading.Thread(
                target=auth_worker,
                args=(self.server.account, self.server.services),
                daemon=True,
            ).start()
            self._json({"ok": True})

        elif path == "/redirect":
            body = self._body()
            url  = body.get("url", "").strip()
            if not url:
                self._json({"ok": False, "msg": "No URL provided"}, 400)
                return
            if "code=" not in url and "error=" not in url:
                self._json({"ok": False, "msg": "Doesn't look like an OAuth callback (no code= parameter)"}, 400)
                return
            ok, msg = feed_redirect_url(url)
            self._json({"ok": ok, "msg": msg}, 200 if ok else 409)

        else:
            self.send_error(404)


def main():
    ap = argparse.ArgumentParser(description="gog OAuth tunnel \u2014 access from iPhone over VPN")
    ap.add_argument("--port",     type=int, default=DEFAULT_PORT)
    ap.add_argument("--host",     type=str, default="0.0.0.0")
    ap.add_argument("--account",  type=str, default=DEFAULT_ACCOUNT,
                    help="Account passed to: gog auth add <ACCOUNT>")
    ap.add_argument("--services", type=str, default=DEFAULT_SERVICES,
                    help="Passed to --services flag (default: user)")
    args = ap.parse_args()

    if not args.account:
        print("\n  \u26a0  Specify --account me@example.com  (or set DEFAULT_ACCOUNT in the script)\n")
        ap.print_help()
        sys.exit(1)

    try:
        import socket
        ips = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
               if not ip.startswith("127.")]
    except Exception:
        ips = []

    print(f"\n  gog Auth \u2014 port {args.port}")
    print(f"  Command: gog auth add {args.account} --services {args.services} --manual\n")
    for ip in ips:
        print(f"  \u2192 http://{ip}:{args.port}   \u2190 open on iPhone (VPN on)")
    print(f"  \u2192 http://localhost:{args.port}\n")

    srv = HTTPServer((args.host, args.port), Handler)
    srv.port     = args.port
    srv.account  = args.account
    srv.services = args.services
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")


if __name__ == "__main__":
    main()
