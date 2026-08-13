'use strict';

/**
 * 공유 그림판 서버 (외부 패키지 없이 순수 Node.js)
 *
 *   node server.js            → 3000번 포트
 *   $env:PORT=8080; node server.js
 *
 * 같은 네트워크(사내망/공유기)에 있는 사람들이 http://<내PC IP>:<포트> 로 접속하면
 * 하나의 캔버스에 실시간으로 함께 그리고, 채팅으로 대화할 수 있습니다.
 */

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const os = require('os');

const PORT = Number(process.env.PORT) || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');

// 캔버스 논리 크기 — 모든 좌표는 이 기준으로 주고받는다(화면 크기 달라도 동일하게 보이도록).
const CANVAS_W = 1600;
const CANVAS_H = 900;

const MAX_HISTORY = 80000;  // 저장할 획 조각 수 (초과 시 오래된 것부터 버림)
const MAX_CHAT = 200;       // 저장할 채팅 수
const MAX_FRAME = 4 * 1024 * 1024;

const PEER_COLORS = [
  '#e11d48', '#2563eb', '#059669', '#d97706', '#7c3aed',
  '#0891b2', '#db2777', '#65a30d', '#ea580c', '#4f46e5',
];

// ─────────────────────────────────────────────── 접속 암호

/**
 * ROOM_PASSWORD 환경변수로 지정한다.
 *   - 값을 주면      → 그 값이 접속 암호
 *   - 'off' 로 주면  → 암호 없이 개방 (사내망 전용으로만 쓸 것)
 *   - 지정하지 않으면 → 6자리 숫자를 자동 생성해 콘솔에 표시
 */
const PW_ENV = process.env.ROOM_PASSWORD;
const NO_PASSWORD = PW_ENV != null && PW_ENV.toLowerCase() === 'off';
const PASSWORD = NO_PASSWORD ? null
  : (PW_ENV && PW_ENV.length ? PW_ENV : String(crypto.randomInt(100000, 1000000)));
const PASSWORD_GENERATED = !NO_PASSWORD && !(PW_ENV && PW_ENV.length);

const COOKIE = 'paint_session';
const SESSION_HOURS = 12;
const SECRET = crypto.randomBytes(32); // 서버를 껐다 켜면 모두 다시 로그인해야 한다

function issueToken() {
  const exp = String(Date.now() + SESSION_HOURS * 3600 * 1000);
  const sig = crypto.createHmac('sha256', SECRET).update(exp).digest('hex');
  return exp + '.' + sig;
}

function tokenValid(token) {
  if (!token) return false;
  const parts = String(token).split('.');
  if (parts.length !== 2) return false;
  const exp = Number(parts[0]);
  if (!Number.isFinite(exp) || Date.now() > exp) return false;
  const good = Buffer.from(crypto.createHmac('sha256', SECRET).update(parts[0]).digest('hex'));
  const got = Buffer.from(parts[1]);
  return good.length === got.length && crypto.timingSafeEqual(good, got);
}

function readCookie(req, name) {
  const raw = req.headers.cookie;
  if (!raw) return null;
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return null;
}

function authed(req) {
  return NO_PASSWORD || tokenValid(readCookie(req, COOKIE));
}

function clientIp(req) {
  const fwd = req.headers['x-forwarded-for'];
  if (typeof fwd === 'string' && fwd.length) return fwd.split(',')[0].trim();
  return req.socket.remoteAddress || '?';
}

// 무차별 대입 방지 — IP당 10분에 10회까지
const attempts = new Map();
function tooManyAttempts(ip) {
  const now = Date.now();
  const a = attempts.get(ip);
  if (!a || now > a.until) return false;
  return a.count >= 10;
}
function noteFailure(ip) {
  const now = Date.now();
  const a = attempts.get(ip);
  if (!a || now > a.until) attempts.set(ip, { count: 1, until: now + 10 * 60 * 1000 });
  else a.count++;
}
setInterval(() => {
  const now = Date.now();
  for (const [ip, a] of attempts) if (now > a.until) attempts.delete(ip);
}, 60000).unref();

function loginPage(error) {
  return `<!DOCTYPE html>
<html lang="ko"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>공유 그림판 — 입장</title>
<style>
  html,body{height:100%;margin:0;background:#0f1115;color:#e7eaf0;
    font-family:"Malgun Gothic","맑은 고딕",-apple-system,"Segoe UI",sans-serif;
    display:flex;align-items:center;justify-content:center}
  form{background:#181b22;border:1px solid #2e3440;border-radius:14px;
    padding:32px 30px;width:320px;text-align:center}
  h1{margin:0 0 6px;font-size:19px}
  p{margin:0 0 22px;font-size:13px;color:#949cad}
  input{width:100%;background:#21252e;border:1px solid #2e3440;color:#e7eaf0;
    border-radius:9px;padding:12px;font-size:16px;text-align:center;
    letter-spacing:3px;font-family:inherit}
  input:focus{outline:none;border-color:#4f8cff}
  button{width:100%;margin-top:12px;background:#4f8cff;border:none;color:#fff;
    border-radius:9px;padding:12px;font-size:14px;font-weight:700;cursor:pointer;
    font-family:inherit}
  .err{margin-top:14px;color:#f87171;font-size:13px}
</style></head>
<body>
  <form method="POST" action="/login">
    <h1>🎨 공유 그림판</h1>
    <p>접속 암호를 입력하세요</p>
    <input type="password" name="password" autofocus autocomplete="current-password" placeholder="암호">
    <button type="submit">입장</button>
    ${error ? `<div class="err">${error}</div>` : ''}
  </form>
</body></html>`;
}

function sendLogin(res, status, error) {
  res.writeHead(status, {
    'Content-Type': 'text/html; charset=utf-8',
    'Cache-Control': 'no-store',
  }).end(loginPage(error));
}

// ─────────────────────────────────────────────── 정적 파일 서버

const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon',
};

const isSecure = (req) => req.headers['x-forwarded-proto'] === 'https';

const server = http.createServer((req, res) => {
  const urlPath = decodeURIComponent((req.url || '/').split('?')[0]);

  // 암호 확인
  if (req.method === 'POST' && urlPath === '/login') {
    const ip = clientIp(req);
    if (tooManyAttempts(ip)) {
      sendLogin(res, 429, '시도 횟수가 너무 많습니다. 10분 뒤에 다시 시도하세요.');
      return;
    }
    let body = '';
    req.on('data', (c) => {
      body += c;
      if (body.length > 2000) req.destroy();
    });
    req.on('end', () => {
      let given = '';
      try {
        given = new URLSearchParams(body).get('password') || '';
      } catch { /* 잘못된 본문 */ }

      const a = Buffer.from(given);
      const b = Buffer.from(PASSWORD || '');
      const ok = a.length === b.length && crypto.timingSafeEqual(a, b);

      if (!ok) {
        noteFailure(ip);
        console.log(`[!] 암호 오류 — ${ip}`);
        sendLogin(res, 401, '암호가 맞지 않습니다.');
        return;
      }
      res.writeHead(302, {
        'Location': '/',
        'Set-Cookie': `${COOKIE}=${issueToken()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_HOURS * 3600}` +
          (isSecure(req) ? '; Secure' : ''),
      }).end();
    });
    return;
  }

  if (!authed(req)) {
    sendLogin(res, 200, null);
    return;
  }

  const rel = urlPath === '/' ? 'index.html' : urlPath.replace(/^\/+/, '');
  const filePath = path.join(PUBLIC_DIR, rel);

  // 디렉터리 탈출 방지
  if (!filePath.startsWith(PUBLIC_DIR)) {
    res.writeHead(403).end('Forbidden');
    return;
  }

  fs.readFile(filePath, (err, data) => {
    if (err) {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' }).end('찾을 수 없습니다');
      return;
    }
    res.writeHead(200, {
      'Content-Type': MIME[path.extname(filePath).toLowerCase()] || 'application/octet-stream',
      'Cache-Control': 'no-cache',
    }).end(data);
  });
});

// ─────────────────────────────────────────────── WebSocket (RFC 6455 최소 구현)

const GUID = '258EAFA5-E914-47DA-95CA-C5AB0DC85B11';

function encodeFrame(opcode, payload) {
  const len = payload.length;
  let header;
  if (len < 126) {
    header = Buffer.alloc(2);
    header[1] = len;
  } else if (len < 65536) {
    header = Buffer.alloc(4);
    header[1] = 126;
    header.writeUInt16BE(len, 2);
  } else {
    header = Buffer.alloc(10);
    header[1] = 127;
    header.writeUInt32BE(0, 2);
    header.writeUInt32BE(len, 6);
  }
  header[0] = 0x80 | opcode; // FIN + opcode
  return Buffer.concat([header, payload]);
}

/** 소켓으로 들어온 바이트를 프레임 단위로 잘라 콜백에 넘긴다. */
function feed(state, chunk, handlers) {
  state.buf = state.buf.length ? Buffer.concat([state.buf, chunk]) : chunk;

  for (;;) {
    const b = state.buf;
    if (b.length < 2) return;

    const fin = (b[0] & 0x80) !== 0;
    const opcode = b[0] & 0x0f;
    const masked = (b[1] & 0x80) !== 0;
    let len = b[1] & 0x7f;
    let off = 2;

    if (len === 126) {
      if (b.length < off + 2) return;
      len = b.readUInt16BE(off);
      off += 2;
    } else if (len === 127) {
      if (b.length < off + 8) return;
      if (b.readUInt32BE(off) !== 0) return handlers.close(1009); // 4GB 이상은 취급 안 함
      len = b.readUInt32BE(off + 4);
      off += 8;
    }
    if (len > MAX_FRAME) return handlers.close(1009);

    let mask = null;
    if (masked) {
      if (b.length < off + 4) return;
      mask = b.subarray(off, off + 4);
      off += 4;
    }
    if (b.length < off + len) return;

    let payload = b.subarray(off, off + len);
    if (masked) {
      const out = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) out[i] = payload[i] ^ mask[i & 3];
      payload = out;
    } else {
      payload = Buffer.from(payload);
    }
    state.buf = b.subarray(off + len);

    if (opcode === 0x8) return handlers.close(1000);
    if (opcode === 0x9) { handlers.pong(payload); continue; }
    if (opcode === 0xA) continue; // pong 무시

    if (opcode === 0x0) {
      // 이어지는 조각
      state.frag = state.frag ? Buffer.concat([state.frag, payload]) : payload;
    } else if (opcode === 0x1 || opcode === 0x2) {
      state.fragOp = opcode;
      state.frag = payload;
    }

    if (fin && state.frag) {
      const full = state.frag;
      state.frag = null;
      if (state.fragOp === 0x1) handlers.message(full.toString('utf8'));
    }
  }
}

// ─────────────────────────────────────────────── 방 상태

let nextId = 1;
const clients = new Map(); // id → client
const history = [];        // 지금까지 그려진 획 조각들
const chatLog = [];
let gridOn = false;        // 참여자별 칸 나누기 사용 여부

/** 참여자 수에 맞는 격자 크기. 4명이면 2×2, 5~6명이면 3×2 식으로 나뉜다. */
function gridLayout(n) {
  const cols = Math.max(1, Math.ceil(Math.sqrt(n)));
  return { cols, rows: Math.max(1, Math.ceil(n / cols)) };
}

/** 이 사람에게 배정된 칸의 영역. 접속 순서대로 왼쪽 위부터 채운다. */
function cellOf(clientId) {
  const ids = [...clients.keys()].sort((a, b) => a - b);
  const idx = ids.indexOf(clientId);
  if (idx < 0) return null;

  const { cols, rows } = gridLayout(ids.length);
  const cw = CANVAS_W / cols;
  const ch = CANVAS_H / rows;
  const cx = idx % cols;
  const cy = Math.floor(idx / cols);
  return { x0: cx * cw, y0: cy * ch, x1: (cx + 1) * cw, y1: (cy + 1) * ch };
}

function send(c, obj) {
  if (c.socket.destroyed) return;
  try {
    c.socket.write(encodeFrame(0x1, Buffer.from(JSON.stringify(obj), 'utf8')));
  } catch { /* 끊긴 소켓은 무시 */ }
}

function broadcast(obj, exceptId) {
  for (const c of clients.values()) {
    if (c.id !== exceptId) send(c, obj);
  }
}

function peerList() {
  return [...clients.values()].map((c) => ({ id: c.id, name: c.name, color: c.color }));
}

function pushPeers() {
  broadcast({ t: 'peers', peers: peerList() });
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const COLOR_RE = /^#[0-9a-fA-F]{6}$/;

function cleanName(v) {
  return String(v ?? '').replace(/\s+/g, ' ').trim().slice(0, 20);
}

server.on('upgrade', (req, socket) => {
  const key = req.headers['sec-websocket-key'];
  if (!key) return socket.destroy();

  // 암호를 통과하지 못한 연결은 여기서 끊는다
  if (!authed(req)) {
    socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
    return socket.destroy();
  }

  const accept = crypto.createHash('sha1').update(key + GUID).digest('base64');
  socket.write(
    'HTTP/1.1 101 Switching Protocols\r\n' +
    'Upgrade: websocket\r\n' +
    'Connection: Upgrade\r\n' +
    `Sec-WebSocket-Accept: ${accept}\r\n\r\n`
  );
  socket.setNoDelay(true);

  const id = nextId++;
  const client = {
    id,
    socket,
    name: `게스트${id}`,
    color: PEER_COLORS[(id - 1) % PEER_COLORS.length],
    state: { buf: Buffer.alloc(0), frag: null, fragOp: 0 },
  };
  clients.set(id, client);

  const close = () => {
    if (!clients.has(id)) return;
    clients.delete(id);
    socket.destroy();
    broadcast({ t: 'leave', id });
    pushPeers();
    console.log(`[-] ${client.name} 접속 종료 (현재 ${clients.size}명)`);
  };

  send(client, {
    t: 'init',
    id,
    color: client.color,
    name: client.name,
    canvas: { w: CANVAS_W, h: CANVAS_H },
    grid: gridOn,
    history,
    chat: chatLog,
    peers: peerList(),
  });
  pushPeers();
  console.log(`[+] ${client.name} 접속 (현재 ${clients.size}명)`);

  socket.on('data', (chunk) => {
    feed(client.state, chunk, {
      close,
      pong: (payload) => socket.write(encodeFrame(0xA, payload)),
      message: (text) => handle(client, text),
    });
  });
  socket.on('error', close);
  socket.on('close', close);
});

function handle(client, text) {
  let msg;
  try { msg = JSON.parse(text); } catch { return; }
  if (!msg || typeof msg !== 'object') return;

  switch (msg.t) {
    case 'hello': {
      const name = cleanName(msg.name);
      if (!name) return;
      client.name = name;
      pushPeers();
      return;
    }

    case 'seg': {
      // 획 한 조각 — 저장해 두었다가 나중에 들어온 사람에게 그대로 재생해 준다.
      // by/sid 는 실행취소 때 "누구의 몇 번째 획인지" 찾는 데 쓴다.
      const x0 = num(msg.x0), y0 = num(msg.y0), x1 = num(msg.x1), y1 = num(msg.y1);
      const sid = num(msg.sid);
      if (x0 === null || y0 === null || x1 === null || y1 === null || sid === null) return;

      // 칸 나누기 중이면 자기 칸을 벗어난 획은 받지 않는다
      if (gridOn) {
        const cell = cellOf(client.id);
        const eps = 1;
        if (!cell ||
            x0 < cell.x0 - eps || x0 > cell.x1 + eps || y0 < cell.y0 - eps || y0 > cell.y1 + eps ||
            x1 < cell.x0 - eps || x1 > cell.x1 + eps || y1 < cell.y0 - eps || y1 > cell.y1 + eps) {
          return;
        }
      }

      const seg = {
        t: 'seg',
        by: client.id,
        sid,
        x0: clamp(x0, -50, CANVAS_W + 50),
        y0: clamp(y0, -50, CANVAS_H + 50),
        x1: clamp(x1, -50, CANVAS_W + 50),
        y1: clamp(y1, -50, CANVAS_H + 50),
        w: clamp(num(msg.w) ?? 4, 1, 120),
        c: COLOR_RE.test(msg.c) ? msg.c : '#111111',
        e: !!msg.e,
      };

      history.push(seg);
      if (history.length > MAX_HISTORY) history.splice(0, history.length - MAX_HISTORY);
      broadcast(seg, client.id);
      return;
    }

    case 'undo': {
      // 이 사람이 그린 획 중 아직 남아 있는 가장 마지막 것을 통째로 지운다.
      let target = null;
      for (let i = history.length - 1; i >= 0; i--) {
        if (history[i].by === client.id) { target = history[i].sid; break; }
      }
      if (target === null) return;

      for (let i = history.length - 1; i >= 0; i--) {
        if (history[i].by === client.id && history[i].sid === target) history.splice(i, 1);
      }
      broadcast({ t: 'undo', by: client.id, sid: target });  // 보낸 사람에게도 전달된다
      return;
    }

    case 'grid': {
      gridOn = !!msg.on;
      broadcast({ t: 'grid', on: gridOn, by: client.name });  // 보낸 사람에게도 전달된다
      console.log(`[=] ${client.name} 님이 칸 나누기를 ${gridOn ? '켰습니다' : '껐습니다'}`);
      return;
    }

    case 'cursor': {
      const x = num(msg.x), y = num(msg.y);
      if (x === null || y === null) return;
      broadcast({ t: 'cursor', id: client.id, x, y }, client.id);
      return;
    }

    case 'clear': {
      history.length = 0;
      broadcast({ t: 'clear', by: client.name });  // 보낸 사람에게도 전달된다
      console.log(`[!] ${client.name} 님이 캔버스를 전체 지웠습니다`);
      return;
    }

    case 'chat': {
      const body = String(msg.text ?? '').trim().slice(0, 500);
      if (!body) return;
      const entry = {
        id: client.id,
        name: client.name,
        color: client.color,
        text: body,
        ts: Date.now(),
      };
      chatLog.push(entry);
      if (chatLog.length > MAX_CHAT) chatLog.splice(0, chatLog.length - MAX_CHAT);
      broadcast({ t: 'chat', msg: entry });  // 보낸 사람에게도 전달된다
      return;
    }
  }
}

// 30초마다 ping — 유휴 연결이 조용히 끊기는 것을 막는다.
setInterval(() => {
  for (const c of clients.values()) {
    if (!c.socket.destroyed) {
      try { c.socket.write(encodeFrame(0x9, Buffer.alloc(0))); } catch { /* noop */ }
    }
  }
}, 30000).unref();

// ─────────────────────────────────────────────── 시작

server.listen(PORT, '0.0.0.0', () => {
  const addrs = [];
  for (const list of Object.values(os.networkInterfaces())) {
    for (const ni of list || []) {
      if (ni.family === 'IPv4' && !ni.internal) addrs.push(ni.address);
    }
  }

  console.log('');
  console.log('  공유 그림판 서버가 켜졌습니다.');
  console.log('  ─────────────────────────────────────────');
  console.log(`  내 PC        : http://localhost:${PORT}`);
  for (const a of addrs) {
    console.log(`  같은 네트워크 : http://${a}:${PORT}`);
  }
  console.log('  ─────────────────────────────────────────');

  if (NO_PASSWORD) {
    console.log('  ⚠  암호 없음 (ROOM_PASSWORD=off)');
    console.log('     주소를 아는 사람은 누구나 들어옵니다. 사내망 전용으로만 쓰세요.');
  } else if (PASSWORD_GENERATED) {
    console.log(`  접속 암호     : ${PASSWORD}   ← 이 암호를 함께 전달하세요`);
    console.log('     (자동 생성됨. 서버를 다시 켜면 암호가 바뀝니다)');
    console.log('     고정하려면  $env:ROOM_PASSWORD="원하는암호"  후 실행');
  } else {
    console.log('  접속 암호     : ROOM_PASSWORD 로 지정한 값');
  }

  console.log('  ─────────────────────────────────────────');
  console.log('  ※ 종료하려면 Ctrl+C');
  console.log('');
});
