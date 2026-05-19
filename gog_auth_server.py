#!/usr/bin/env python3
"""
gog_auth_server.py — Tunnels the OAuth loopback redirect from iPhone to the box.

Flow:
  1. Open http://<box-vpn-ip>:7080 on iPhone (VPN connected)
  2. Tap "Start Auth" — box runs gog and shows the Google URL
  3. Tap the Google link — sign in — Safari lands on failed 127.0.0.1/callback?code=…
  4. Tap the "Send to gog" bookmark — bookmarklet POSTs the URL here automatically
  5. Done. Box feeds the full redirect URL to gog stdin, auth completes.

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

# ── Defaults ──────────────────────────────────────────────────────────────────
DEFAULT_PORT     = 7080
DEFAULT_ACCOUNT  = ""        # set via --account or edit here: "me@example.com"
DEFAULT_SERVICES = "user"

GOOGLE_URL_RE = re.compile(r"https?://accounts\.google\.[a-z.]+/\S+")

# ── Shared state ──────────────────────────────────────────────────────────────
state = {
    "phase":   "idle",   # idle | running | need_redirect | submitting | done | error
    "gog_url": None,     # Google OAuth URL to show to user
    "log":     [],
    "result":  None,
    "proc":    None,
}
_lock = threading.Lock()


# ── Auth worker ───────────────────────────────────────────────────────────────
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

        # Read stdout until the Google URL appears
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

        # Wait for /redirect to deliver the callback URL
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

        # Drain remaining output and wait
        rest = proc.stdout.read()
        proc.wait()
        with _lock:
            for l in rest.splitlines():
                state["log"].append(l)
            if proc.returncode == 0:
                state["phase"]  = "done"
                state["result"] = "Authentication successful ✓"
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


# ── HTML page ─────────────────────────────────────────────────────────────────
HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,maximum-scale=1">
<title>gog Auth</title>
<style>
:root{--bg:#0f1117;--card:#1a1d27;--bdr:#2a2d3a;--tx:#e2e4f0;--mt:#7b7f96;
  --bl:#4f8ef7;--gr:#3ecf8e;--rd:#f75f5f;--yw:#f7c948}
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
.url-box a{color:var(--bl);text-decoration:none}
.step{font-size:.82rem;color:var(--mt);margin-top:14px;margin-bottom:5px;line-height:1.5}
.step b{color:var(--tx)}
.bk-box{background:#11131e;border:1px solid var(--bdr);border-radius:9px;
  padding:11px 13px;font-family:monospace;font-size:.7rem;color:var(--yw);
  word-break:break-all;line-height:1.6;margin:8px 0}
.copy-btn{width:100%;padding:10px;border:1px solid var(--bdr);border-radius:8px;
  background:transparent;color:var(--mt);font-size:.82rem;cursor:pointer}
.copy-btn:active{background:var(--bdr)}
input[type=text]{width:100%;padding:11px 13px;border-radius:9px;border:1px solid var(--bdr);
  background:#11131e;color:var(--tx);font-size:.85rem;margin:6px 0 10px;outline:none;
  display:block}
input[type=text]:focus{border-color:var(--bl)}
.result{margin-top:14px;padding:12px 14px;border-radius:10px;font-size:.88rem;line-height:1.5}
.result.done{background:#1a2e24;color:var(--gr);border:1px solid #2a4a3a}
.result.error{background:#2e1a1a;color:var(--rd);border:1px solid #4a2a2a}
hr{border:none;border-top:1px solid var(--bdr);margin:20px 0}
.log-toggle{background:none;border:none;color:var(--mt);font-size:.75rem;
  cursor:pointer;text-decoration:underline;padding:0;display:block;margin-top:14px}
.log{margin-top:8px;background:#0a0c13;border:1px solid var(--bdr);border-radius:8px;
  padding:10px 12px;font-family:monospace;font-size:.72rem;color:var(--mt);
  max-height:140px;overflow-y:auto;white-space:pre-wrap;word-break:break-all;display:none}
.spin{display:inline-block;width:13px;height:13px;border:2px solid #2a2d3a;
  border-top-color:var(--bl);border-radius:50%;animation:sp .7s linear infinite;
  vertical-align:middle;margin-right:5px}
@keyframes sp{to{transform:rotate(360deg)}}
</style>
</head>
<body>
<div class="card">
  <h1>&#128273; gog Auth Tunnel</h1>
  <p class="sub" id="acct-line">Loading…</p>
  <span id="badge" class="badge idle">idle</span>
  <div id="main"></div>

  <hr>
  <p class="step"><b>One-time Safari setup</b> — save this as a bookmark:</p>
  <div class="bk-box" id="bk"></div>
  <button class="copy-btn" onclick="copyBk()">&#128203; Copy bookmarklet</button>
  <p class="step" style="font-size:.74rem">
    In Safari: tap &#128279; Share &rarr; Add Bookmark &rarr; then <b>edit the URL</b> and replace it with the copied text.<br>
    Name it <b>"Send to gog"</b>. Tap it after signing in on the failed redirect page.
  </p>

  <button class="log-toggle" onclick="toggleLog()">Show raw log</button>
  <div class="log" id="log"></div>
</div>

<script>
const ORIGIN = location.origin;

// Build bookmarklet with the correct box URL baked in
const bkJS = `javascript:(function(){`
  + `var u=location.href;`
  + `fetch('${ORIGIN}/redirect',{method:'POST',`
  + `headers:{'Content-Type':'application/json'},`
  + `body:JSON.stringify({url:u})})`
  + `.then(r=>r.json())`
  + `.then(d=>{document.documentElement.innerHTML=`
  + `d.ok?'<body style="font:22px/2 sans-serif;padding:30px;background:#0f1117;color:#3ecf8e">&#10003; Sent to gog!<br><small style=color:#7b7f96>Auth completing on box…</small></body>'`
  + `:'<body style="font:18px/2 sans-serif;padding:30px;background:#0f1117;color:#f75f5f">&#10007; '+d.msg+'</body>';})`
  + `.catch(e=>alert('Failed: '+e));`
  + `})()`;
document.getElementById('bk').textContent = bkJS;

function copyBk(){
  navigator.clipboard.writeText(bkJS).then(()=>{
    const b=document.querySelector('.copy-btn');
    b.textContent='&#10003; Copied!';
    setTimeout(()=>b.textContent='&#128203; Copy bookmarklet',2500);
  }).catch(()=>{
    // Fallback: select the text
    const el=document.getElementById('bk');
    const r=document.createRange(); r.selectNode(el);
    window.getSelection().removeAllRanges();
    window.getSelection().addRange(r);
  });
}

function render(s){
  document.getElementById('acct-line').textContent =
    'Account: '+(s.account||'—')+' · Services: '+(s.services||'—');

  const badge=document.getElementById('badge');
  badge.className='badge '+s.phase;
  const L={idle:'idle',running:'connecting…',need_redirect:'waiting for redirect',
    submitting:'processing…',done:'authenticated ✓',error:'error'};
  badge.textContent=L[s.phase]||s.phase;

  const mc=document.getElementById('main');
  if(s.phase==='idle'){
    mc.innerHTML=`<button class="btn bp" onclick="startAuth()">Start authentication</button>`;
  } else if(s.phase==='running'){
    mc.innerHTML=`<button class="btn bm"><span class="spin"></span>Launching gog…</button>`;
  } else if(s.phase==='need_redirect'){
    mc.innerHTML=`
      <p class="step"><b>1</b> &mdash; Tap to open Google sign-in:</p>
      <div class="url-box"><a href="${s.gog_url}" target="_blank">&#128279; Open Google sign-in &nearr;</a></div>
      <p class="step"><b>2</b> &mdash; Sign in. Safari will land on a <b>failed page</b> (<code>127.0.0.1:…</code>).</p>
      <p class="step"><b>3</b> &mdash; Tap your <b>"Send to gog"</b> bookmark. Done.</p>
      <hr style="margin:16px 0">
      <p class="step">Or paste the redirect URL manually:</p>
      <input type="text" id="mu" placeholder="http://127.0.0.1:…/?code=…">
      <button class="btn bg" onclick="submitManual()">Submit redirect URL &rarr;</button>`;
  } else if(s.phase==='submitting'){
    mc.innerHTML=`<button class="btn bm"><span class="spin"></span>Completing auth…</button>`;
  } else if(s.phase==='done'){
    mc.innerHTML=`<div class="result done">&#10003; ${s.result}</div>
      <button class="btn bp" style="margin-top:14px" onclick="startAuth()">Auth again</button>`;
    stopPoll();
  } else if(s.phase==='error'){
    mc.innerHTML=`<div class="result error">&#10007; ${s.result}</div>
      <button class="btn bp" style="margin-top:14px" onclick="startAuth()">Try again</button>`;
    stopPoll();
  }

  if(s.log?.length) document.getElementById('log').textContent=s.log.join('\\n');
}

async function startAuth(){
  await fetch('/start',{method:'POST'});
  startPoll();
}

async function submitManual(){
  const u=document.getElementById('mu')?.value?.trim();
  if(!u){alert('Paste the redirect URL first.');return;}
  const r=await fetch('/redirect',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({url:u})});
  const d=await r.json();
  if(!d.ok) alert('Error: '+d.msg);
  else startPoll();
}

let timer=null,active=false;
function startPoll(){if(!active){active=true;poll();}}
function stopPoll(){active=false;clearTimeout(timer);}
async function poll(){
  if(!active)return;
  try{
    const s=await fetch('/state').then(r=>r.json());
    render(s);
    if(s.phase!=='done'&&s.phase!=='error') timer=setTimeout(poll,800);
  }catch(e){timer=setTimeout(poll,2000);}
}
function toggleLog(){
  const el=document.getElementById('log');
  el.style.display=el.style.display==='none'?'block':'none';
}

fetch('/state').then(r=>r.json()).then(render);
</script>
</body>
</html>"""


# ── HTTP handler ──────────────────────────────────────────────────────────────
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
                self._json({"ok": False, "msg": "URL doesn't look like an OAuth callback (missing code=)"}, 400)
                return
            ok, msg = feed_redirect_url(url)
            self._json({"ok": ok, "msg": msg}, 200 if ok else 409)

        else:
            self.send_error(404)


# ── Entry point ───────────────────────────────────────────────────────────────
def main():
    ap = argparse.ArgumentParser(description="gog OAuth loopback tunnel — access from iPhone over VPN")
    ap.add_argument("--port",     type=int, default=DEFAULT_PORT)
    ap.add_argument("--host",     type=str, default="0.0.0.0")
    ap.add_argument("--account",  type=str, default=DEFAULT_ACCOUNT,
                    help="Account passed to: gog auth add <ACCOUNT>")
    ap.add_argument("--services", type=str, default=DEFAULT_SERVICES,
                    help="Passed to --services flag (default: user)")
    args = ap.parse_args()

    if not args.account:
        print("\n  ⚠  Specify --account me@example.com  (or set DEFAULT_ACCOUNT in the script)\n")
        ap.print_help()
        sys.exit(1)

    try:
        import socket
        ips = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2]
               if not ip.startswith("127.")]
    except Exception:
        ips = []

    print(f"\n  gog Auth Tunnel — port {args.port}")
    print(f"  Running: gog auth add {args.account} --services {args.services} --manual\n")
    for ip in ips:
        print(f"  → http://{ip}:{args.port}   ← open this on iPhone (VPN on)")
    print(f"  → http://localhost:{args.port}")
    print()

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
