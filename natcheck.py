#!/usr/bin/env python3
"""
NAT Type Full Detector (Twin-Server Architecture) — Single-file
================================================================
Usage on Primary Machine (Server A, e.g. 1.1.1.1):
    pip install aiohttp
    python natcheck.py --mode primary --port 8080 --secondary-url http://<Server_B_IP>:8081

Usage on Secondary Machine (Server B, e.g. 2.2.2.2):
    pip install aiohttp
    python natcheck.py --mode secondary --port 8081

Detection capability (Twin server architecture):
    ✅ Public/Open Internet (no NAT)
    ✅ Symmetric NAT (Endpoint/Address Dependent Mapping)
    ✅ Full Cone NAT (Endpoint-Independent Filtering)
    ✅ Address-Restricted Cone NAT
    ✅ Port-Restricted Cone NAT
    ✅ UDP Blocked

Algorithm:
    1. Browser creates one RTCPeerConnection and gathers candidates to 
       STUN(Primary:3478), STUN(Primary:3479), and STUN(Secondary:3478).
    2. Primary node analyzes the mapped ports to distinguish Symmetric vs Cone mapping.
    3. Primary node instructs Secondary node to send an unsolicited ICE STUN Binding 
       Request to the browser's mapped port. 
       - If browser replies (Full Cone), the NAT allows unsolicited traffic from new IPs.
    4. Primary node sends an unsolicited ICE STUN Request from an ephemeral port.
       - If browser replies (Address Restricted), the NAT allows traffic from the same IP.
"""

import asyncio
import socket
import struct
import json
import sys
import os
import logging
import hmac
import hashlib
import binascii
import argparse
import urllib.parse
from aiohttp import web, ClientSession

logging.basicConfig(level=logging.INFO, format="%(asctime)s  %(message)s")
log = logging.getLogger("natcheck")

MAGIC = 0x2112A442

# ─── STUN Protocol Helpers ────────────────────────────────────────────────────

def make_ice_binding_request(b_ufrag, s_ufrag, b_pwd):
    """Craft an ICE Binding Request to trigger WebRTC Peer Reflexive responses."""
    trans_id = os.urandom(12)
    username = f"{b_ufrag}:{s_ufrag}".encode('utf-8')
    
    # 0x0006 USERNAME - pad to 4 bytes boundary
    pad_len = (4 - (len(username) % 4)) % 4
    padded_user = username + b'\x00' * pad_len
    attr_user = struct.pack(">HH", 0x0006, len(username)) + padded_user
    
    # 0x0024 PRIORITY
    prio = struct.pack(">I", 1853824767)
    attr_prio = struct.pack(">HH4s", 0x0024, 4, prio)
    
    # 0x0025 USE-CANDIDATE
    attr_use = struct.pack(">HH", 0x0025, 0)
    
    # Message length up to MESSAGE-INTEGRITY (24 bytes for integrity attr format)
    msg_len_integrity = len(attr_user) + len(attr_prio) + len(attr_use) + 24
    header = struct.pack(">HHI12s", 0x0001, msg_len_integrity, MAGIC, trans_id)
    msg_pre_mac = header + attr_user + attr_prio + attr_use
    
    # 0x0008 MESSAGE-INTEGRITY (HMAC-SHA1)
    mac = hmac.new(b_pwd.encode('utf-8'), msg_pre_mac, hashlib.sha1).digest()
    attr_integ = struct.pack(">HH20s", 0x0008, 20, mac)
    
    # Add FINGERPRINT
    msg_len_finger = msg_len_integrity + 8
    header_final = struct.pack(">HHI12s", 0x0001, msg_len_finger, MAGIC, trans_id)
    msg_pre_finger = header_final + attr_user + attr_prio + attr_use + attr_integ
    
    crc = (binascii.crc32(msg_pre_finger) & 0xffffffff) ^ 0x5354554E
    attr_finger = struct.pack(">HHI", 0x8028, 4, crc)
    
    return msg_pre_finger + attr_finger


def _parse_request(data: bytes):
    if len(data) < 20: return None
    if struct.unpack(">H", data[:2])[0] != 0x0001: return None
    if struct.unpack(">I", data[4:8])[0] != MAGIC: return None
    return data[8:20]


def _build_response(tx: bytes, ip: str, port: int) -> bytes:
    ip_xor   = struct.unpack(">I", socket.inet_aton(ip))[0] ^ MAGIC
    port_xor = port ^ (MAGIC >> 16)
    attr_val = struct.pack(">BBH I", 0, 1, port_xor, ip_xor)   # XOR-MAPPED-ADDRESS
    attr     = struct.pack(">HH", 0x0020, len(attr_val)) + attr_val
    header   = struct.pack(">HHI12s", 0x0101, len(attr), MAGIC, tx)
    return header + attr


def _start_stun_udp(port: int, loop: asyncio.AbstractEventLoop):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", port))
    sock.setblocking(False)

    def _on_packet():
        try:
            data, addr = sock.recvfrom(2048)
        except Exception:
            return
        tx = _parse_request(data)
        if tx:
            sock.sendto(_build_response(tx, addr[0], addr[1]), addr)

    loop.add_reader(sock, _on_packet)
    log.info("Started STUN server on UDP :%d", port)
    return sock


# ─── Active Probing Core ──────────────────────────────────────────────────────

async def send_active_probe(target_ip, target_port, b_ufrag, b_pwd, s_ufrag):
    """Sends ICE Binding Request to target and waits 1s for Binding Response."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.bind(('', 0))  # Any ephemeral port to test filtering
    
    req = make_ice_binding_request(b_ufrag, s_ufrag, b_pwd)
    
    loop = asyncio.get_event_loop()
    sock.sendto(req, (target_ip, target_port))
    
    fut = loop.create_future()
    
    def on_read():
        try:
            data, addr = sock.recvfrom(2048)
            if not fut.done() and len(data) >= 20:
                msg_type = struct.unpack(">H", data[:2])[0]
                # Check for Binding Success Response or Error Response
                if msg_type in (0x0101, 0x0111):
                    fut.set_result(True)
        except Exception:
            pass
            
    loop.add_reader(sock, on_read)
    
    success = False
    try:
        await asyncio.wait_for(fut, timeout=1.0)
        success = True
    except asyncio.TimeoutError:
        success = False
    finally:
        loop.remove_reader(sock)
        sock.close()
        
    return success


async def req_secondary_probe(sec_url, pld):
    """Asks the Secondary Node to perform an active probe."""
    try:
        url = sec_url.rstrip("/") + "/api/probe"
        async with ClientSession() as session:
            async with session.post(url, json=pld, timeout=3.0) as r:
                ans = await r.json()
                return ans.get("success", False)
    except Exception as e:
        log.error("Secondary probe to %s failed: %s", sec_url, e)
        return False


# ─── HTTP Endpoints ───────────────────────────────────────────────────────────

async def api_probe(request: web.Request) -> web.Response:
    body = await request.json()
    success = await send_active_probe(
        body['target_ip'], body['target_port'], 
        body['req_ufrag'], body['req_pwd'], body['server_ufrag']
    )
    return web.json_response({"success": success})


async def api_analyze(request: web.Request) -> web.Response:
    body = await request.json()
    local_ips = set(body.get("localIPs", []))
    srflx = body.get("srflx", [])
    b_ufrag = body.get("browser_ufrag")
    b_pwd = body.get("browser_pwd")
    s_ufrag = body.get("server_ufrag")

    # Mappings deduplicated by port
    seen_ports = set()
    for c in srflx:
        seen_ports.add(c["port"])
        
    n = len(seen_ports)

    if n == 0:
        return web.json_response({"type": "blocked", "label": "UDP 被屏蔽", "details": "无法获取公共 IP。防火墙可能拦截了 UDP。"})

    if n > 1:
        ports = ", ".join(str(p) for p in seen_ports)
        return web.json_response({
            "type": "symmetric", "label": "对称型 NAT（Symmetric）",
            "details": f"映射端口不固定 ({ports})。P2P 穿透困难，需要 TURN 中继。"
        })

    # Ext IP/Port is stable (Cone NAT or Open)
    ext_ip = srflx[0]["ip"]
    ext_port = srflx[0]["port"]

    if ext_ip in local_ips:
        return web.json_response({
            "type": "open", "label": "公网/直连（Open Internet）",
            "details": f"IP {ext_ip} 直接暴露在公网，无 NAT 环境。"
        })

    sec_url = request.app['config'].secondary_url
    if not sec_url:
        return web.json_response({
            "type": "cone", "label": "锥形 NAT (未检测子类型)",
            "details": f"已识别为 Endpoint-Independent Mapping (映射到 {ext_ip}:{ext_port})。要区分 Full/Restricted 锥形，需要在服务器端配置 --secondary-url。"
        })

    log.info("Testing Cone NAT filtering behavior for %s:%d", ext_ip, ext_port)

    # Test 1: Full Cone Probe (via Secondary IP)
    pld = {"target_ip": ext_ip, "target_port": ext_port, "req_ufrag": b_ufrag, "req_pwd": b_pwd, "server_ufrag": s_ufrag}
    full_cone = await req_secondary_probe(sec_url, pld)
    
    if full_cone:
        return web.json_response({
            "type": "full_cone", "label": "全锥形 NAT（Full Cone）",
            "details": "外部任意主机的入站 UDP 都可以畅通无阻，P2P 条件最优。"
        })

    # Test 2: Address-Restricted Cone Probe (via Primary IP, ephemeral port)
    addr_rest = await send_active_probe(ext_ip, ext_port, b_ufrag, b_pwd, s_ufrag)
    if addr_rest:
        return web.json_response({
            "type": "addr_rest_cone", "label": "地址受限锥形 NAT（Address-Restricted）",
            "details": "同 IP 其他端口的包可以通过，P2P 条件良好。"
        })

    # Fallback Test 3: Port-Restricted
    return web.json_response({
        "type": "port_rest_cone", "label": "端口受限锥形 NAT（Port-Restricted）",
        "details": "只有之前通讯过的目标端口才能回传包。可以通过 STUN 打洞实现 P2P。"
    })


# ─── HTML Frontend ────────────────────────────────────────────────────────────

HTML = r"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>高级 NAT 类型检测</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --bg:      #0f172a; var(--surface): #1e293b; var(--card): #0f172a;
  --border:  #334155; --text: #f8fafc; --text-muted: #94a3b8;
  --primary: #3b82f6; --success: #10b981; --warning: #f59e0b; --danger: #ef4444; --magenta: #d946ef;
}
* { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Inter', sans-serif; }
body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 1.5rem; }
.card { background: var(--surface); border: 1px solid var(--border); border-radius: 16px; padding: 2.5rem; max-width: 500px; width: 100%; box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5); }
h1 { font-size: 1.75rem; text-align: center; margin-bottom: 0.5rem; background: linear-gradient(to right, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }
.subtitle { text-align: center; color: var(--text-muted); font-size: 0.9rem; margin-bottom: 2rem; }
.btn { width: 100%; padding: 1rem; border: none; border-radius: 8px; background: var(--primary); color: white; font-weight: 600; font-size: 1rem; cursor: pointer; transition: 0.2s ease; }
.btn:hover:not(:disabled) { background: #2563eb; }
.btn:disabled { opacity: 0.5; cursor: wait; }
.logs { margin-top: 1.5rem; background: #0b1120; border-radius: 8px; padding: 1rem; font-family: monospace; font-size: 0.8rem; color: #a5b4fc; height: 160px; overflow-y: auto; border: 1px solid var(--border); }
.logs div { margin-bottom: 0.3rem; }
.result-box { display: none; margin-top: 1.5rem; padding: 1.5rem; border-radius: 12px; text-align: center; animation: slideUp 0.3s ease; }
@keyframes slideUp { from { transform: translateY(10px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }
.result-box h2 { font-size: 1.4rem; margin-bottom: 0.5rem; }
.result-box p { font-size: 0.9rem; opacity: 0.9; line-height: 1.5; }

.t-open { background: rgba(16,185,129,0.15); border: 1px solid var(--success); color: #34d399; }
.t-cone { background: rgba(59,130,246,0.15); border: 1px solid var(--primary); color: #93c5fd; }
.t-full_cone { background: rgba(59,130,246,0.15); border: 1px solid var(--primary); color: #93c5fd; }
.t-addr_rest_cone { background: rgba(217,70,239,0.15); border: 1px solid var(--magenta); color: #f0abfc; }
.t-port_rest_cone { background: rgba(245,158,11,0.15); border: 1px solid var(--warning); color: #fcd34d; }
.t-symmetric { background: rgba(239,68,68,0.15); border: 1px solid var(--danger); color: #fca5a5; }
.t-blocked { background: #334155; border: 1px solid #475569; color: #cbd5e1; }
</style>
</head>
<body>
<div class="card">
  <h1>NAT 类型检测</h1>
  <div class="subtitle">Twin-Server 深度穿透探测 / RFC-5245</div>
  <button id="startBtn" class="btn" onclick="startTest()">开始检测探测</button>
  <div id="logs" class="logs"><div>System ready.</div></div>
  <div id="result" class="result-box"></div>
</div>

<script>
window.SECONDARY_HOST = "{{SECONDARY_HOST}}";
const PRIMARY_HOST = location.hostname;

function log(msg) {
  const c = document.getElementById('logs');
  const d = document.createElement('div');
  d.textContent = `> ${msg}`;
  c.appendChild(d);
  c.scrollTop = c.scrollHeight;
}

async function gatherCandidates() {
  log(`Initializing WebRTC ICE Agent...`);
  const iceServers = [
    { urls: 'stun:' + PRIMARY_HOST + ':3478' },
    { urls: 'stun:' + PRIMARY_HOST + ':3479' }
  ];
  if (window.SECONDARY_HOST) {
    iceServers.push({ urls: 'stun:' + window.SECONDARY_HOST + ':3478' });
  }

  const pc = new RTCPeerConnection({ iceServers });
  pc.createDataChannel('probe');
  
  const hostSet = new Set();
  const srflxSet = new Map();
  let resolved = false;

  let bUfrag = '', bPwd = '';
  // Fake secondary peer to force ICE into checking state
  const sUfrag = Math.random().toString(36).substring(2, 10);
  const sPwd = (Math.random().toString(36).substring(2) + Math.random().toString(36).substring(2) + "abcdefghijklmnop").substring(0, 26);

  return new Promise(async (resolve, reject) => {
    const complete = () => {
      if (resolved) return; resolved = true;
      log(`Gathered ${srflxSet.size} unique srflx mappings.`);
      window._pc_keepalive = pc;
      resolve({
        localIPs: [...hostSet], srflx: [...srflxSet.values()],
        browser_ufrag: bUfrag, browser_pwd: bPwd, server_ufrag: sUfrag
      });
    };

    pc.onicecandidate = e => {
      if (!e.candidate) { log("ICE gathering completed."); complete(); return; }
      const cand = e.candidate.candidate;
      log(`Candidate: ${cand.split(' ').slice(4, 8).join(' ')}`);
      
      const parts = cand.split(' ');
      const ip = parts[4], port = parseInt(parts[5]), typ = parts[7];
      if (typ === 'host' && ip && !ip.startsWith('169.254') && ip !== '0.0.0.0' && !ip.includes(':')) {
        hostSet.add(ip);
      }
      if (typ === 'srflx') srflxSet.set(ip + ':' + port, { ip, port });
    };

    try {
      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      log(`Offer created. Listening on local port...`);
      
      const uMatch = offer.sdp.match(/a=ice-ufrag:(.+)/);
      const pMatch = offer.sdp.match(/a=ice-pwd:(.+)/);
      if (uMatch) bUfrag = uMatch[1].trim();
      if (pMatch) bPwd = pMatch[1].trim();

      // Munge SDP answer to simulate remote peer
      let lines = offer.sdp.split('\n');
      let ansLines = [];
      for (let l of lines) {
        l = l.trim(); if (!l) continue;
        if (l.startsWith('a=setup:')) ansLines.push('a=setup:active');
        else if (l.startsWith('a=ice-ufrag:')) ansLines.push('a=ice-ufrag:' + sUfrag);
        else if (l.startsWith('a=ice-pwd:')) ansLines.push('a=ice-pwd:' + sPwd);
        else if (l.includes('candidate:')) continue;
        else if (l.startsWith('a=ice-options:')) continue;
        else ansLines.push(l);
      }
      // Add fake remote candidate to enter checking state
      ansLines.push('a=candidate:1 1 udp 2113937151 192.0.2.1 9 typ host');
      
      await pc.setRemoteDescription({ type: 'answer', sdp: ansLines.join('\r\n') + '\r\n' });
      log(`Dummy RemoteDescription applied. Active response enabled.`);
    } catch (e) { reject(e); }

    // Wait max 3.5 seconds
    setTimeout(complete, 3500);
  });
}

async function startTest() {
  const btn = document.getElementById('startBtn');
  btn.disabled = true; document.getElementById('result').style.display = 'none';
  document.getElementById('logs').innerHTML = '';

  try {
    const data = await gatherCandidates();
    log(`Sending context to server for deep active inspection...`);
    log(`Awaiting active filtering UDP probes...`);
    
    // Server performs active probes
    const res = await fetch('/api/analyze', {
      method: 'POST', body: JSON.stringify(data),
      headers: { 'Content-Type': 'application/json' }
    });
    
    const json = await res.json();
    log(`Server detection result: ${json.type}`);
    
    const rBox = document.getElementById('result');
    rBox.className = 'result-box t-' + json.type;
    rBox.innerHTML = `<h2>${json.label}</h2><p>${json.details}</p>`;
    rBox.style.display = 'block';

  } catch(e) {
    log(`Error: ${e.message}`);
  } finally {
    btn.disabled = false;
  }
}
</script>
</body>
</html>
"""

async def index(request):
    sec_host = ""
    cfg = request.app['config']
    if cfg.secondary_url:
        parsed = urllib.parse.urlparse(cfg.secondary_url)
        sec_host = parsed.hostname or ""
    html = HTML.replace("{{SECONDARY_HOST}}", sec_host)
    return web.Response(text=html, content_type="text/html")


# ─── App Setup ────────────────────────────────────────────────────────────────

def parse_args():
    parser = argparse.ArgumentParser(description="Multi-IP WebRTC NAT Detector")
    parser.add_argument("--mode", choices=["primary", "secondary"], default="primary")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--secondary-url", help="URL of secondary server (e.g. http://1.2.3.4:8081)")
    return parser.parse_args()


@web.middleware
async def cors_middleware(request, handler):
    if request.method == 'OPTIONS':
        return web.Response(status=200, headers={
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type',
        })
    try:
        response = await handler(request)
        if isinstance(response, web.StreamResponse):
            response.headers['Access-Control-Allow-Origin'] = '*'
        return response
    except web.HTTPException as ex:
        ex.headers['Access-Control-Allow-Origin'] = '*'
        raise

async def main():
    args = parse_args()
    loop = asyncio.get_event_loop()

    app = web.Application(middlewares=[cors_middleware])
    app['config'] = args

    if args.mode == "primary":
        _start_stun_udp(3478, loop)
        _start_stun_udp(3479, loop)
        app.router.add_get("/", index)
        app.router.add_post("/api/analyze", api_analyze)
        log.info("Running in PRIMARY mode.")
        if args.secondary_url:
            log.info("Paired with secondary node at: %s", args.secondary_url)
        else:
            log.warning("No secondary URL provided. Filtering tests (Full Cone) skipped.")
            
    elif args.mode == "secondary":
        _start_stun_udp(3478, loop)
        app.router.add_post("/api/probe", api_probe)
        log.info("Running in SECONDARY mode.")

    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", args.port)
    await site.start()

    log.info("HTTP API listening on port %d", args.port)
    await asyncio.Event().wait()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        log.info("Shutting down.")
