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

/** 획 한 조각이 이 칸 안에 완전히 들어가는지 */
function segInCell(s, cell) {
  const e = 1;
  return s.x0 >= cell.x0 - e && s.x0 <= cell.x1 + e && s.y0 >= cell.y0 - e && s.y0 <= cell.y1 + e &&
         s.x1 >= cell.x0 - e && s.x1 <= cell.x1 + e && s.y1 >= cell.y0 - e && s.y1 <= cell.y1 + e;
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

// ─────────────────────────────────────────────── 빙고

let bingo = null;  // { size, boards:Map(id→숫자배열), called, order, turnIdx, goal, over, winners }

/** 1 ~ size² 를 섞은 판 하나. 사람마다 배열이 다르다. */
function shuffledBoard(size) {
  const a = [];
  for (let i = 1; i <= size * size; i++) a.push(i);
  for (let i = a.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    const tmp = a[i]; a[i] = a[j]; a[j] = tmp;
  }
  return a;
}

/** 가로·세로·대각선 중 완성된 줄 수 */
function countLines(board, size, called) {
  const hit = (r, c) => called.has(board[r * size + c]);
  let lines = 0;

  for (let r = 0; r < size; r++) {
    let ok = true;
    for (let c = 0; c < size; c++) if (!hit(r, c)) { ok = false; break; }
    if (ok) lines++;
  }
  for (let c = 0; c < size; c++) {
    let ok = true;
    for (let r = 0; r < size; r++) if (!hit(r, c)) { ok = false; break; }
    if (ok) lines++;
  }
  let d1 = true, d2 = true;
  for (let i = 0; i < size; i++) {
    if (!hit(i, i)) d1 = false;
    if (!hit(i, size - 1 - i)) d2 = false;
  }
  if (d1) lines++;
  if (d2) lines++;
  return lines;
}

/** 아직 접속 중인 다음 사람에게 차례를 넘긴다. */
function advanceTurn() {
  if (!bingo) return;
  for (let k = 0; k < bingo.order.length; k++) {
    bingo.turnIdx = (bingo.turnIdx + 1) % bingo.order.length;
    if (clients.has(bingo.order[bingo.turnIdx])) return;
  }
}

/** 차례가 넘어갈 때마다 제한시간을 다시 잡는다. turnMs 가 0 이면 제한 없음. */
function resetTurnDeadline() {
  if (!bingo) return;
  bingo.turnDeadline = (bingo.over || !bingo.turnMs) ? 0 : Date.now() + bingo.turnMs;
}

/** 숫자 하나를 부른다. 사람이 고른 경우와 시간초과 자동 선택이 같은 경로를 쓴다. */
function bingoCall(callerId, pick, auto) {
  if (!bingo || bingo.over) return;
  if (bingo.called.indexOf(pick) >= 0) return;

  const who = clients.has(callerId) ? clients.get(callerId).name : "?";
  bingo.called.push(pick);
  broadcast({ t: "sys", text: `${who} 님이 ${pick} 을(를) 불렀습니다${auto ? " (시간 초과 — 자동 선택)" : ""}` });

  const called = new Set(bingo.called);
  const winners = [];
  for (const pid of bingo.order) {
    if (!clients.has(pid)) continue;
    const lines = countLines(bingo.boards.get(pid), bingo.size, called);
    if (lines >= bingo.goal) winners.push({ id: pid, name: clients.get(pid).name, lines });
  }

  if (winners.length) {
    bingo.over = true;
    bingo.winners = winners;
    bingo.turnDeadline = 0;
    broadcast({ t: "sys", text: `🎉 ${winners.map((w) => w.name).join(", ")} 님 빙고! (${bingo.goal}줄 달성)` });
  } else {
    advanceTurn();
    resetTurnDeadline();
  }
}

// 제한시간이 지나면 그 사람 판에서 아직 안 나온 숫자를 무작위로 부른다.
setInterval(() => {
  if (!bingo || bingo.over || !bingo.turnDeadline) return;
  if (Date.now() < bingo.turnDeadline) return;

  const id = bingo.order[bingo.turnIdx];
  const board = bingo.boards.get(id);
  if (!clients.has(id) || !board) { advanceTurn(); resetTurnDeadline(); sendBingo(); return; }

  const called = new Set(bingo.called);
  const free = board.filter((v) => !called.has(v));
  if (!free.length) { advanceTurn(); resetTurnDeadline(); sendBingo(); return; }

  bingoCall(id, free[crypto.randomInt(free.length)], true);
  sendBingo();
}, 500).unref();

/** 판은 사람마다 다르므로 각자에게 자기 판을 실어 보낸다. */
function sendBingo(only) {
  const targets = only ? [only] : [...clients.values()];

  if (!bingo) {
    for (const c of targets) send(c, { t: 'bingo', on: false });
    return;
  }

  const called = new Set(bingo.called);
  const players = bingo.order
    .filter((id) => clients.has(id))
    .map((id) => ({
      id,
      name: clients.get(id).name,
      color: clients.get(id).color,
      lines: countLines(bingo.boards.get(id), bingo.size, called),
    }));

  const turnId = bingo.order[bingo.turnIdx];
  const base = {
    t: 'bingo', on: true,
    size: bingo.size, goal: bingo.goal,
    called: bingo.called,
    turn: turnId,
    turnName: clients.has(turnId) ? clients.get(turnId).name : '—',
    over: bingo.over, winners: bingo.winners,
    turnMs: bingo.turnMs,
    // 기기 시계가 서로 다를 수 있으니 남은 시간(ms)만 보낸다
    turnLeft: bingo.turnDeadline ? Math.max(0, bingo.turnDeadline - Date.now()) : 0,
    players,
  };

  for (const c of targets) {
    send(c, Object.assign({ board: bingo.boards.get(c.id) || null }, base));
  }
}

// ─────────────────────────────────────────────── 라이어 게임

const LIAR_TOPICS = {
  '음식': ['김치찌개', '피자', '치킨', '초밥', '떡볶이', '삼겹살', '짜장면', '비빔밥', '햄버거', '파스타', '냉면', '탕수육', '만두', '라면', '순대'],
  '동물': ['코끼리', '펭귄', '기린', '호랑이', '고양이', '강아지', '원숭이', '악어', '돌고래', '부엉이', '다람쥐', '캥거루', '낙타', '판다', '거북이'],
  '직업': ['의사', '교사', '소방관', '요리사', '가수', '운동선수', '경찰', '변호사', '미용사', '사진작가', '승무원', '농부', '기자', '건축가', '수의사'],
  '장소': ['도서관', '놀이공원', '병원', '영화관', '수영장', '공항', '시장', '카페', '헬스장', '미술관', '주유소', '편의점', '목욕탕', '캠핑장', '동물원'],
  '여행': ['에펠탑', '만리장성', '피라미드', '나이아가라폭포', '산토리니', '하와이', '오로라', '사파리', '크루즈', '온천', '면세점', '캐리어', '여권', '비행기', '리조트'],
  '사물': ['우산', '시계', '냉장고', '자전거', '청소기', '거울', '안경', '베개', '가위', '드라이기', '전자레인지', '칫솔', '에어컨', '헬멧', '충전기'],
  '스포츠': ['축구', '야구', '농구', '수영', '골프', '테니스', '스키', '복싱', '배드민턴', '볼링', '태권도', '양궁', '마라톤', '서핑', '피겨스케이팅'],
};

let liar = null;  // { phase, category, word, liarId, order, votes:Map, result }

const pick = (arr) => arr[crypto.randomInt(arr.length)];
const normalize = (s) => String(s || '').replace(/\s+/g, '').toLowerCase();

function shuffleIds(ids) {
  const a = ids.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = crypto.randomInt(i + 1);
    const tmp = a[i]; a[i] = a[j]; a[j] = tmp;
  }
  return a;
}

/** 게임을 끝내고 결과를 확정한다. */
function finishLiar(citizensWin, extra) {
  const counts = new Map();
  for (const [voter, target] of liar.votes) {
    if (!clients.has(voter)) continue;
    counts.set(target, (counts.get(target) || 0) + 1);
  }
  liar.phase = 'done';
  liar.result = Object.assign({
    liarId: liar.liarId,
    liarName: clients.has(liar.liarId) ? clients.get(liar.liarId).name : '(나감)',
    word: liar.word,
    category: liar.category,
    fool: liar.fool,
    decoyWord: liar.decoyWord,
    decoyCategory: liar.decoyCategory,
    citizensWin,
    counts: [...counts.entries()].map(([id, n]) => ({
      id, n, name: clients.has(id) ? clients.get(id).name : '(나감)',
    })).sort((a, b) => b.n - a.n),
  }, extra || {});

  broadcast({
    t: 'sys',
    text: citizensWin
      ? `🔎 시민 승리! 라이어는 ${liar.result.liarName} 님이었습니다 (제시어: ${liar.word})`
      : `🕵 라이어 승리! 라이어는 ${liar.result.liarName} 님이었습니다 (제시어: ${liar.word})`,
  });
}

/** 모두 투표했으면 개표한다. */
function tallyLiar() {
  const voters = liar.order.filter((id) => clients.has(id));
  if (voters.some((id) => !liar.votes.has(id))) return;   // 아직 안 낸 사람이 있다

  const counts = new Map();
  for (const [voter, target] of liar.votes) {
    if (!clients.has(voter)) continue;
    counts.set(target, (counts.get(target) || 0) + 1);
  }
  let top = null, max = 0, tie = false;
  for (const [id, n] of counts) {
    if (n > max) { max = n; top = id; tie = false; }
    else if (n === max) tie = true;
  }

  if (!tie && top === liar.liarId) {
    // 라이어가 지목당했다 — 제시어를 맞히면 뒤집을 기회를 준다
    liar.phase = 'guess';
    broadcast({ t: 'sys', text: `라이어가 지목됐습니다. 라이어에게 제시어를 맞힐 기회가 주어집니다` });
  } else {
    finishLiar(false, { tie, topId: top });
  }
}

function sendLiar(only) {
  const targets = only ? [only] : [...clients.values()];

  if (!liar) {
    for (const c of targets) send(c, { t: 'liar', on: false });
    return;
  }

  const alive = liar.order.filter((id) => clients.has(id));
  const base = {
    t: 'liar', on: true,
    phase: liar.phase,
    category: liar.category,
    result: liar.result,
    players: alive.map((id) => ({
      id,
      name: clients.get(id).name,
      color: clients.get(id).color,
      voted: liar.votes.has(id),
    })),
  };

  for (const c of targets) {
    const isLiar = c.id === liar.liarId;
    const inGame = liar.order.indexOf(c.id) >= 0;
    const done = liar.phase === 'done';

    // 바보 라이어 모드에서는 라이어 본인에게 "너는 라이어다"라고 알리지 않는다.
    // 대신 전혀 다른 주제의 엉뚱한 제시어를 주고, 자기가 시민인 줄 알게 둔다.
    // (지목당해 최후의 기회로 넘어가거나 게임이 끝나면 그때 밝혀진다)
    const fooled = liar.fool && isLiar && !done && liar.phase !== 'guess';

    let word = null;
    let category = liar.category;
    let tellIsLiar = isLiar;

    if (done) {
      word = liar.word;                                  // 끝나면 모두에게 공개
    } else if (fooled) {
      word = liar.decoyWord;
      category = liar.decoyCategory;
      tellIsLiar = false;
    } else if (inGame && !isLiar) {
      word = liar.word;
    }

    send(c, Object.assign({}, base, {
      category,
      isLiar: tellIsLiar,
      word,
      fool: liar.fool,   // 어떤 모드인지는 공개 정보 (누가 라이어인지와 무관)
      spectator: !inGame,
      myVote: liar.votes.has(c.id) ? liar.votes.get(c.id) : null,
    }));
  }
}

// ─────────────────────────────────────────────── 활쏘기

// 화면 좌표는 캔버스(1600×900) 기준. 물리 계산과 점수 판정은 전부 서버가 한다.
const AR = {
  bowX: 240, bowY: 630,        // 활 위치
  groundY: 790,
  centerY: 460,                // 과녁 중심 높이
  targetR: 105,                // 과녁 반지름
  gravity: 950,                // px/s²
  vMax: 1450,                  // 힘 1.0 일 때 초기 속도
  dt: 1 / 120,
  maxT: 8,
  sample: 4,                   // 몇 스텝마다 궤적을 기록할지 (1/30초 간격)
  moveAmp: 150,
  movePeriod: 4000,
  dists: { near: 820, mid: 1120, far: 1400 },
  winds: { none: 0, weak: 240, strong: 500 },
};

let arch = null;
const r1 = (v) => Math.round(v * 10) / 10;

/** 움직이는 과녁의 현재 높이 */
function targetYAt(ms) {
  if (!arch || !arch.moving) return AR.centerY;
  const t = (ms - arch.mvT0) / AR.movePeriod * Math.PI * 2;
  return AR.centerY + AR.moveAmp * Math.sin(t);
}

function newWind() {
  const w = AR.winds[arch.windMode] || 0;
  return w ? Math.round((crypto.randomInt(2001) / 1000 - 1) * w) : 0;
}

/** 화살 궤적을 계산한다. 과녁 평면을 지나면 그 높이를, 아니면 땅에 떨어진 지점을 돌려준다. */
function flyArrow(angle, power, wind, targetX) {
  const v = AR.vMax * power;
  let x = AR.bowX, y = AR.bowY;
  let vx = Math.cos(angle) * v, vy = Math.sin(angle) * v;
  const pts = [[r1(x), r1(y)]];
  let t = 0, step = 0;

  while (t < AR.maxT) {
    const px = x, py = y;
    vx += wind * AR.dt;
    vy += AR.gravity * AR.dt;
    x += vx * AR.dt;
    y += vy * AR.dt;
    t += AR.dt;
    step++;

    if (px < targetX && x >= targetX) {          // 과녁 평면 통과
      const f = (targetX - px) / (x - px);
      const hy = py + (y - py) * f;
      pts.push([r1(targetX), r1(hy)]);
      return { pts, t, hitY: hy, onTarget: true };
    }
    if (y >= AR.groundY) {                        // 땅에 떨어짐
      const f = (AR.groundY - py) / (y - py);
      const hx = px + (x - px) * f;
      pts.push([r1(hx), r1(AR.groundY)]);
      return { pts, t, groundX: hx, onTarget: false };
    }
    if (step % AR.sample === 0) pts.push([r1(x), r1(y)]);
    if (x > CANVAS_W + 300 || pts.length > 900) break;
  }
  pts.push([r1(x), r1(y)]);
  return { pts, t, onTarget: false };
}

/** 과녁 중심에서 얼마나 벗어났는지로 점수를 매긴다 */
function ringScore(dy) {
  const R = AR.targetR;
  const d = Math.abs(dy);
  if (d <= R * 0.2) return 10;
  if (d <= R * 0.4) return 8;
  if (d <= R * 0.6) return 6;
  if (d <= R * 0.8) return 4;
  if (d <= R) return 2;
  return 0;
}

function resetArchDeadline() {
  if (!arch) return;
  arch.turnDeadline = (arch.phase !== 'aim' || !arch.turnMs) ? 0 : Date.now() + arch.turnMs;
}

function archRanking() {
  return [...arch.scores.entries()]
    .filter(([id]) => clients.has(id))
    .map(([id, sc]) => {
      const c = clients.get(id);
      return { id, name: c.name, color: c.color, total: sc.total, shots: sc.shots.slice() };
    })
    .sort((a, b) => b.total - a.total);
}

function finishArch(reason) {
  arch.phase = 'done';
  arch.turnDeadline = 0;
  arch.results = archRanking();
  const top = arch.results[0];
  broadcast({
    t: 'sys',
    text: reason || (top ? `🏹 활쏘기 종료 — ${top.name} 님 우승 (${top.total}점)` : '🏹 활쏘기 종료'),
  });
}

/** 아직 쏠 화살이 남은 다음 사람에게 차례를 넘긴다. */
function nextArcher() {
  if (!arch) return;
  for (let k = 0; k < arch.order.length; k++) {
    arch.turnIdx = (arch.turnIdx + 1) % arch.order.length;
    const id = arch.order[arch.turnIdx];
    const sc = arch.scores.get(id);
    if (clients.has(id) && sc && sc.shots.length < arch.shotsPer) {
      arch.phase = 'aim';
      arch.wind = newWind();          // 매 차례마다 바람이 바뀐다
      resetArchDeadline();
      return;
    }
  }
  finishArch();
}

function doShoot(id, angle, power, auto) {
  if (!arch || arch.phase !== 'aim') return;
  if (arch.order[arch.turnIdx] !== id) return;
  const sc = arch.scores.get(id);
  if (!sc || sc.shots.length >= arch.shotsPer) return;

  const a = clamp(angle, -1.5, 0.35);      // 항상 앞쪽으로만 쏠 수 있다
  const pw = clamp(power, 0.15, 1);
  const sim = flyArrow(a, pw, arch.wind, arch.targetX);

  let score = 0, hx = null, hy = null;
  if (sim.onTarget) {
    const cy = targetYAt(Date.now() + sim.t * 1000);   // 움직이는 과녁은 도착 시점 높이로 판정
    score = ringScore(sim.hitY - cy);
    hx = arch.targetX;
    hy = sim.hitY;
  } else if (sim.groundX != null) {
    hx = sim.groundX;
    hy = AR.groundY;
  }

  sc.shots.push(score);
  sc.total += score;

  const c = clients.get(id);
  if (hx != null) {
    arch.arrows.push({ x: r1(hx), y: r1(hy), s: score, c: c ? c.color : '#888' });
    if (arch.arrows.length > 60) arch.arrows.splice(0, arch.arrows.length - 60);
  }

  arch.shotId++;
  arch.shot = {
    id: arch.shotId,
    pts: sim.pts,
    score,
    by: id,
    name: c ? c.name : '?',
    color: c ? c.color : '#888',
    auto: !!auto,
  };
  arch.phase = 'fly';
  arch.turnDeadline = 0;
  arch.resumeAt = Date.now() + Math.min(3000, sim.t * 1000) + 900;

  broadcast({
    t: 'sys',
    text: `${c ? c.name : '?'} 님 ${score ? score + '점' : '빗나감'}${auto ? ' (시간 초과 — 자동 발사)' : ''}`,
  });
}

// 차례 제한시간과 화살 비행 종료를 함께 처리한다
setInterval(() => {
  if (!arch) return;
  const now = Date.now();

  if (arch.phase === 'fly') {
    if (now >= arch.resumeAt) { nextArcher(); sendArch(); }
    return;
  }
  if (arch.phase === 'aim' && arch.turnDeadline && now >= arch.turnDeadline) {
    const id = arch.order[arch.turnIdx];
    if (!clients.has(id)) { nextArcher(); sendArch(); return; }
    // 자동 발사 — 대충 앞쪽 위로
    const a = -0.9 + crypto.randomInt(500) / 1000;
    const pw = 0.55 + crypto.randomInt(350) / 1000;
    doShoot(id, a, pw, true);
    sendArch();
  }
}, 200).unref();

function sendArch(only) {
  const targets = only ? [only] : [...clients.values()];

  if (!arch) {
    for (const c of targets) send(c, { t: 'arch', on: false });
    return;
  }

  const turnId = arch.order[arch.turnIdx];
  const msg = {
    t: 'arch', on: true,
    phase: arch.phase,
    geo: {
      bowX: AR.bowX, bowY: AR.bowY, groundY: AR.groundY,
      centerY: AR.centerY, targetR: AR.targetR,
      gravity: AR.gravity, vMax: AR.vMax,
      targetX: arch.targetX,
      moveAmp: AR.moveAmp, movePeriod: AR.movePeriod,
    },
    moving: arch.moving,
    // 과녁 흔들림은 각자 화면에서 이어서 그린다 (시계 차이를 피하려고 위상만 보낸다)
    mvOff: arch.moving ? (Date.now() - arch.mvT0) % AR.movePeriod : 0,
    wind: arch.wind,
    shotsPer: arch.shotsPer,
    turn: turnId,
    turnName: clients.has(turnId) ? clients.get(turnId).name : '—',
    turnLeft: arch.turnDeadline ? Math.max(0, arch.turnDeadline - Date.now()) : 0,
    arrows: arch.arrows,
    shot: arch.shot,
    results: arch.results,
    players: arch.order.filter((id) => clients.has(id)).map((id) => {
      const c = clients.get(id);
      const sc = arch.scores.get(id) || { total: 0, shots: [] };
      return { id, name: c.name, color: c.color, total: sc.total, shots: sc.shots };
    }),
  };
  for (const c of targets) send(c, msg);
}

// ─────────────────────────────────────────────── 레이싱

// 클라이언트(public/index.html)에도 같은 값이 들어 있다. 한쪽만 고치면 예측이 어긋난다.
const RC = {
  maxSpeed: 520,         // 도로 위 최고 속도 (px/s)
  grassMax: 170,         // 잔디에서의 최고 속도
  accel: 430,
  brake: 620,
  revMax: 180,           // 후진 최고 속도
  turn: 3.1,             // 조향 각속도 (rad/s)
  drag: 0.992,
  grassDrag: 0.90,
  carR: 15,
  tickMs: 33,            // 약 30Hz
  limitMs: 5 * 60 * 1000,
};

/**
 * 코스 중심선들. 극좌표 곡선이라 스스로 교차하지 않는 것이 보장된다
 * (교차하면 체크포인트 판정이 엉킨다).
 * 트랙 좌표는 레이스 시작 시 클라이언트로 그대로 내려보내므로, 여기만 고치면 된다.
 */
function polarTrack(n, base, amp, lobes, ky) {
  const pts = [];
  for (let i = 0; i < n; i++) {
    const a = (i / n) * Math.PI * 2;
    const r = base + amp * Math.cos(lobes * a);
    pts.push({ x: 800 + r * Math.cos(a), y: 450 + r * ky * Math.sin(a) });
  }
  return pts;
}

const TRACKS = [
  {
    name: '기본 오벌',
    halfWidth: 92,
    pts: (() => {
      const p = [];
      for (let i = 0; i < 24; i++) {
        const a = (i / 24) * Math.PI * 2;
        p.push({ x: 800 + 560 * Math.cos(a), y: 450 + 250 * Math.sin(a) + 40 * Math.sin(2 * a) });
      }
      return p;
    })(),
  },
  // 코너 최소반경을 기본 오벌(112px)과 비슷하게 맞췄다. 전속력 회전반경이 168px이라
  // 이보다 훨씬 조이면 기어가듯 달려야 해서 재미가 없다.
  { name: '땅콩 코스', halfWidth: 90, pts: polarTrack(28, 530, 55, 2, 0.58) },   // 최소반경 143
  { name: '물결 서킷', halfWidth: 86, pts: polarTrack(30, 530, 45, 3, 0.56) },   // 최소반경 106
  { name: '클로버 코스', halfWidth: 86, pts: polarTrack(32, 520, 32, 4, 0.60) },  // 최소반경 103
];

function nearestWaypoint(track, x, y) {
  let bi = 0, bd = Infinity;
  for (let i = 0; i < track.length; i++) {
    const dx = track[i].x - x, dy = track[i].y - y;
    const d = dx * dx + dy * dy;
    if (d < bd) { bd = d; bi = i; }
  }
  return bi;
}

/** 중심선까지의 최단 거리. 이 값이 halfWidth를 넘으면 잔디로 나간 것. */
function distToRoad(track, x, y) {
  let best = Infinity;
  const n = track.length;
  for (let i = 0; i < n; i++) {
    const a = track[i], b = track[(i + 1) % n];
    const vx = b.x - a.x, vy = b.y - a.y;
    const len2 = vx * vx + vy * vy;
    let t = len2 ? ((x - a.x) * vx + (y - a.y) * vy) / len2 : 0;
    t = t < 0 ? 0 : t > 1 ? 1 : t;
    const d = Math.hypot(x - (a.x + vx * t), y - (a.y + vy * t));
    if (d < best) best = d;
  }
  return best;
}

let race = null;
let raceTimer = null;

function raceLoopOn() {
  if (!raceTimer) raceTimer = setInterval(raceTick, RC.tickMs);
}
function raceLoopOff() {
  if (raceTimer) { clearInterval(raceTimer); raceTimer = null; }
}

/** 출발 그리드 — 출발선 뒤쪽에 2열로 세운다. */
function gridSpot(track, i) {
  const a = track[0], b = track[1];
  const len = Math.hypot(b.x - a.x, b.y - a.y) || 1;
  const dx = (b.x - a.x) / len, dy = (b.y - a.y) / len;   // 진행 방향
  const nx = -dy, ny = dx;                                 // 좌우 방향
  const row = Math.floor(i / 2), side = (i % 2) ? 1 : -1;
  return {
    x: a.x - dx * (40 + row * 52) + nx * side * 38,
    y: a.y - dy * (40 + row * 52) + ny * side * 38,
    a: Math.atan2(dy, dx),
  };
}

function stepCar(car, dt) {
  const inp = car.input;
  const onRoad = distToRoad(race.track, car.x, car.y) <= race.halfWidth;
  const top = onRoad ? RC.maxSpeed : RC.grassMax;

  if (inp.u) car.speed += RC.accel * dt;
  if (inp.d) car.speed -= RC.brake * dt;
  if (!inp.u && !inp.d) car.speed *= onRoad ? RC.drag : RC.grassDrag;
  else if (!onRoad) car.speed *= RC.grassDrag;

  if (car.speed > top) car.speed = top;
  if (car.speed < -RC.revMax) car.speed = -RC.revMax;
  if (Math.abs(car.speed) < 3) car.speed = 0;

  // 서 있을 때는 방향을 못 바꾼다 (속도에 비례해 조향)
  const grip = Math.min(1, Math.abs(car.speed) / 140);
  const dir = car.speed < 0 ? -1 : 1;
  if (inp.l) car.a -= RC.turn * dt * grip * dir;
  if (inp.r) car.a += RC.turn * dt * grip * dir;

  car.x += Math.cos(car.a) * car.speed * dt;
  car.y += Math.sin(car.a) * car.speed * dt;

  // 화면 밖으로는 못 나간다
  car.x = clamp(car.x, 20, CANVAS_W - 20);
  car.y = clamp(car.y, 20, CANVAS_H - 20);
}

/** 체크포인트를 순서대로 통과해야 한 바퀴로 인정된다 (역주행·질러가기 방지). */
function updateProgress(car, now) {
  const nw = nearestWaypoint(race.track, car.x, car.y);
  const next = (car.cp + 1) % race.track.length;
  if (nw !== next) return;

  car.cp = next;
  if (next !== 0) return;

  car.lap++;
  const t = now - car.lapStart;
  car.lapTimes.push(t);
  if (car.best === null || t < car.best) car.best = t;
  car.lapStart = now;

  if (car.lap >= race.laps) {
    car.finished = true;
    car.finishTime = now - race.startAt;
    race.finishOrder.push(car.id);
    const c = clients.get(car.id);
    broadcast({
      t: 'sys',
      text: `🏁 ${c ? c.name : '?'} 님 완주 — ${race.finishOrder.length}위 (${(car.finishTime / 1000).toFixed(2)}초)`,
    });
  }
}

function resolveCollisions() {
  const cars = [...race.cars.values()].filter((c) => clients.has(c.id) && !c.finished);
  for (let i = 0; i < cars.length; i++) {
    for (let j = i + 1; j < cars.length; j++) {
      const a = cars[i], b = cars[j];
      const dx = b.x - a.x, dy = b.y - a.y;
      const d = Math.hypot(dx, dy);
      const min = RC.carR * 2;
      if (d === 0 || d >= min) continue;
      const push = (min - d) / 2;
      const ux = dx / d, uy = dy / d;
      a.x -= ux * push; a.y -= uy * push;
      b.x += ux * push; b.y += uy * push;
      a.speed *= 0.75; b.speed *= 0.75;
    }
  }
}

function raceRanking() {
  const list = [...race.cars.values()].filter((c) => clients.has(c.id));
  list.sort((a, b) => {
    if (a.finished && b.finished) return a.finishTime - b.finishTime;
    if (a.finished) return -1;
    if (b.finished) return 1;
    const n = race.track.length;
    return (b.lap * n + b.cp) - (a.lap * n + a.cp);
  });
  return list;
}

function endRace(reason) {
  race.phase = 'done';
  race.results = raceRanking().map((c, i) => {
    const cl = clients.get(c.id);
    return {
      id: c.id,
      name: cl ? cl.name : '(나감)',
      color: cl ? cl.color : '#888',
      rank: i + 1,
      finished: c.finished,
      time: c.finishTime,
      best: c.best,
      lap: c.lap,
    };
  });
  raceLoopOff();
  broadcast({ t: 'sys', text: reason || '🏁 레이스가 끝났습니다' });
}

function raceTick() {
  if (!race) return raceLoopOff();
  const now = Date.now();

  if (race.phase === 'countdown') {
    if (now >= race.startAt) {
      race.phase = 'racing';
      for (const c of race.cars.values()) c.lapStart = now;
      broadcast({ t: 'sys', text: '🚦 출발!' });
    }
    sendRace();
    return;
  }

  if (race.phase !== 'racing') { raceLoopOff(); return; }

  const dt = RC.tickMs / 1000;
  for (const car of race.cars.values()) {
    if (car.finished || !clients.has(car.id)) continue;
    stepCar(car, dt);
    updateProgress(car, now);
  }
  resolveCollisions();

  const active = [...race.cars.values()].filter((c) => clients.has(c.id));
  if (!active.length) { endRace('참가자가 모두 나가 레이스를 종료합니다'); }
  else if (active.every((c) => c.finished)) { endRace('🏁 전원 완주!'); }
  else if (now - race.startAt > RC.limitMs) { endRace('⏱ 제한시간 종료'); }

  sendRace();
}

function sendRace(only) {
  const targets = only ? [only] : [...clients.values()];

  if (!race) {
    for (const c of targets) send(c, { t: 'race', on: false });
    return;
  }

  const ranked = raceRanking();
  const rankOf = new Map(ranked.map((c, i) => [c.id, i + 1]));

  const msg = {
    t: 'race', on: true,
    phase: race.phase,
    laps: race.laps,
    trackName: race.trackName,
    countdown: race.phase === 'countdown' ? Math.max(0, race.startAt - Date.now()) : 0,
    elapsed: race.phase === 'racing' ? Date.now() - race.startAt : 0,
    results: race.results || null,
    cars: [...race.cars.values()].filter((c) => clients.has(c.id)).map((c) => {
      const cl = clients.get(c.id);
      return {
        i: c.id,
        n: cl.name,
        c: cl.color,
        x: Math.round(c.x * 10) / 10,
        y: Math.round(c.y * 10) / 10,
        a: Math.round(c.a * 1000) / 1000,
        s: Math.round(c.speed),
        l: c.lap,
        p: c.cp,
        r: rankOf.get(c.id) || 0,
        f: c.finished,
        b: c.best,
      };
    }),
  };

  // 트랙 좌표는 매 틱 보내면 낭비다. 출발 카운트다운 중이거나 특정 한 명에게 보낼 때만
  // 실어 보내고, 클라이언트는 받은 것을 계속 들고 쓴다.
  if (only || race.phase === 'countdown') {
    msg.track = race.track;
    msg.halfWidth = race.halfWidth;
  }

  for (const c of targets) send(c, msg);
}

// ── 물풍선 (크레이지아케이드 식) ───────────────────
// 물풍선을 놓으면 잠시 뒤 십자로 물줄기가 뻗는다. 물줄기에 닿은 사람은 물방울에 갇히고,
// 제한 시간 안에 누군가의 물줄기가 다시 닿아 주면 풀려난다. 못 풀려나면 터져서 탈락.
// 마지막까지 남은 한 명이 이긴다.
//
// 이동·폭발·판정은 전부 여기(서버)에서 한다. 클라이언트가 보내는 것은
// 방향키 눌림 상태와 "풍선 놓기" 요청뿐이고, 나머지는 서버가 다시 계산한다.
const WB = {
  tile: 72, cols: 21, rows: 12,
  ox: 44, oy: 18,              // 1600x900 캔버스 안에서 맵 왼쪽 위 여백
  tickMs: 50,                  // 초당 20번
  half: 23,                    // 캐릭터 충돌 상자 반크기 (칸 36의 2/3 정도)
  baseSpeed: 175, speedStep: 32, maxSpeed: 4,
  fuse: 3000,                  // 풍선이 터지기까지
  waterMs: 700,                // 물줄기가 남아 있는 시간
  trapMs: 6500,                // 물방울에 갇혀 버틸 수 있는 시간
  safeMs: 1600,                // 풀려난 직후 무적
  maxPower: 6, maxBombs: 6,
  boxRate: 0.42,               // 빈칸이 상자가 될 확률
  itemRate: 0.36,              // 상자가 아이템을 떨굴 확률
  glide: 130,                  // 복도로 밀어 넣어 주는 보정 속도
  limitMs: 180000,             // 3분
};

// 출발 자리 — 앞의 4개가 서로 가장 멀다. 격자 벽(짝수,짝수)과 겹치지 않는 칸만 골랐다.
const WB_SPAWNS = [
  [1, 1], [19, 10], [19, 1], [1, 10],
  [9, 1], [11, 10], [1, 5], [19, 5],
];

let wb = null;
let wbTimer = null;

const wbIdx = (tx, ty) => ty * WB.cols + tx;
const wbTileX = (px) => Math.floor((px - WB.ox) / WB.tile);
const wbTileY = (py) => Math.floor((py - WB.oy) / WB.tile);
const wbCX = (tx) => WB.ox + (tx + 0.5) * WB.tile;
const wbCY = (ty) => WB.oy + (ty + 0.5) * WB.tile;
const wbName = (id) => { const c = clients.get(id); return c ? c.name : '나간 사람'; };

/** 0 빈칸 · 1 못 부수는 벽 · 2 상자 */
function wbGenMap() {
  const m = new Array(WB.cols * WB.rows).fill(0);
  for (let y = 0; y < WB.rows; y++) {
    for (let x = 0; x < WB.cols; x++) {
      let v;
      if (x === 0 || y === 0 || x === WB.cols - 1 || y === WB.rows - 1) v = 1;
      else if (x % 2 === 0 && y % 2 === 0) v = 1;   // 가운데 격자 기둥
      else v = Math.random() < WB.boxRate ? 2 : 0;
      m[wbIdx(x, y)] = v;
    }
  }
  // 출발 자리와 그 둘레는 상자를 치워 나올 길을 만들어 준다
  const around = [[0,0],[1,0],[-1,0],[0,1],[0,-1],[2,0],[-2,0],[0,2],[0,-2]];
  for (const sp of WB_SPAWNS) {
    for (const d of around) {
      const tx = sp[0] + d[0], ty = sp[1] + d[1];
      if (tx < 1 || ty < 1 || tx >= WB.cols - 1 || ty >= WB.rows - 1) continue;
      if (m[wbIdx(tx, ty)] === 2) m[wbIdx(tx, ty)] = 0;
    }
  }
  return m;
}

function wbSolid(tx, ty, forId) {
  if (tx < 0 || ty < 0 || tx >= WB.cols || ty >= WB.rows) return true;
  const v = wb.map[wbIdx(tx, ty)];
  if (v === 1 || v === 2) return true;
  for (const b of wb.balloons) {
    if (b.tx !== tx || b.ty !== ty) continue;
    // 발밑에 생긴 풍선은 그 칸에서 완전히 빠져나갈 때까지 통과시켜 준다
    const p = wb.players.get(forId);
    if (p && p.ghost && p.ghost.tx === tx && p.ghost.ty === ty) return false;
    return true;
  }
  return false;
}

/** 충돌 상자가 어떤 칸이라도 막힌 칸에 걸치는가 */
function wbBlocked(x, y, id) {
  const h = WB.half;
  const x0 = wbTileX(x - h), x1 = wbTileX(x + h);
  const y0 = wbTileY(y - h), y1 = wbTileY(y + h);
  for (let ty = y0; ty <= y1; ty++) {
    for (let tx = x0; tx <= x1; tx++) if (wbSolid(tx, ty, id)) return true;
  }
  return false;
}

function wbOverlaps(p, tx, ty) {
  const h = WB.half;
  return wbTileX(p.x - h) <= tx && tx <= wbTileX(p.x + h) &&
         wbTileY(p.y - h) <= ty && ty <= wbTileY(p.y + h);
}

function wbStep(p, dx, dy) {
  if (!dx && !dy) return false;
  if (wbBlocked(p.x + dx, p.y + dy, p.id)) return false;
  p.x += dx; p.y += dy;
  return true;
}

/** 진행 방향이 막혔을 때 직각축을 칸 가운데로 당겨 준다 (복도에 잘 들어가도록) */
function wbGlide(p, axis, dt) {
  const cur = axis === 'x' ? p.x : p.y;
  const mid = axis === 'x' ? wbCX(wbTileX(p.x)) : wbCY(wbTileY(p.y));
  const d = mid - cur;
  if (Math.abs(d) < 0.5) return;
  const step = Math.sign(d) * Math.min(Math.abs(d), WB.glide * dt);
  if (axis === 'x') wbStep(p, step, 0); else wbStep(p, 0, step);
}

function wbMove(p, dt) {
  if (!p.alive || p.trapped) return;
  let vx = 0, vy = 0;
  if (p.input.l) vx -= 1;
  if (p.input.r) vx += 1;
  if (p.input.u) vy -= 1;
  if (p.input.d) vy += 1;
  if (!vx && !vy) return;
  if (vx && vy) { vx *= 0.7071; vy *= 0.7071; }
  p.dir = vx ? (vx > 0 ? 'r' : 'l') : (vy > 0 ? 'd' : 'u');

  const sp = (WB.baseSpeed + p.speed * WB.speedStep) * dt;
  const okX = wbStep(p, vx * sp, 0);
  const okY = wbStep(p, 0, vy * sp);
  if (vx && !okX) wbGlide(p, 'y', dt);
  if (vy && !okY) wbGlide(p, 'x', dt);
}

function wbPlace(p) {
  if (!wb || wb.phase !== 'play' || !p.alive || p.trapped) return;
  const tx = wbTileX(p.x), ty = wbTileY(p.y);
  if (tx < 0 || ty < 0 || tx >= WB.cols || ty >= WB.rows) return;
  if (wb.map[wbIdx(tx, ty)] !== 0) return;
  if (wb.balloons.some((b) => b.tx === tx && b.ty === ty)) return;
  let mine = 0;
  for (const b of wb.balloons) if (b.owner === p.id) mine++;
  if (mine >= p.bombs) return;

  wb.balloons.push({ tx, ty, owner: p.id, power: p.power, at: Date.now() });
  // 그 칸에 서 있던 사람은 모두 빠져나갈 때까지 통과 허용
  for (const q of wb.players.values()) {
    if (q.alive && wbOverlaps(q, tx, ty)) q.ghost = { tx, ty };
  }
}

function wbDropItem(tx, ty) {
  if (Math.random() >= WB.itemRate) return;
  wb.items.push({ tx, ty, k: crypto.randomInt(3) });   // 0 물줄기 · 1 풍선 · 2 스피드
}

/** 풍선 하나를 터뜨린다. 물줄기가 닿은 다른 풍선은 연쇄로 함께 터진다. */
function wbExplode(first) {
  const now = Date.now();
  const bs = ++wb.burstSeq;   // 이 폭발의 번호 — 한 폭발이 같은 사람을 두 번 건드리지 않게 한다
  const queue = [first];
  const seen = new Set([first]);
  const cells = new Map();
  const drops = [];   // 부서진 상자 자리 — 아이템은 물줄기 정리가 끝난 뒤에 놓는다

  const put = (tx, ty, k, by) => {
    const key = tx + ',' + ty;
    const old = cells.get(key);
    if (!old) { cells.set(key, { tx, ty, k, by }); return; }
    if (old.k !== k) old.k = 0;   // 가로와 세로가 겹치면 십자로 그린다
  };

  const dirs = [[1, 0, 1], [-1, 0, 1], [0, 1, 2], [0, -1, 2]];
  while (queue.length) {
    const b = queue.shift();
    const i = wb.balloons.indexOf(b);
    if (i >= 0) wb.balloons.splice(i, 1);
    put(b.tx, b.ty, 0, b.owner);

    for (const d of dirs) {
      for (let step = 1; step <= b.power; step++) {
        const tx = b.tx + d[0] * step, ty = b.ty + d[1] * step;
        if (tx < 0 || ty < 0 || tx >= WB.cols || ty >= WB.rows) break;
        const v = wb.map[wbIdx(tx, ty)];
        if (v === 1) break;                       // 못 부수는 벽에서 멈춘다
        if (v === 2) {                            // 상자는 하나만 부수고 멈춘다
          wb.map[wbIdx(tx, ty)] = 0;
          wb.mapDirty = true;
          drops.push([tx, ty]);
          put(tx, ty, d[2], b.owner);
          break;
        }
        put(tx, ty, d[2], b.owner);
        const other = wb.balloons.find((o) => o.tx === tx && o.ty === ty);
        if (other && !seen.has(other)) { seen.add(other); queue.push(other); }
      }
    }
  }

  for (const c of cells.values()) {
    // 물줄기가 지나간 자리의 아이템은 쓸려 나간다
    for (let i = wb.items.length - 1; i >= 0; i--) {
      if (wb.items[i].tx === c.tx && wb.items[i].ty === c.ty) wb.items.splice(i, 1);
    }
    for (let i = wb.water.length - 1; i >= 0; i--) {
      if (wb.water[i].tx === c.tx && wb.water[i].ty === c.ty) wb.water.splice(i, 1);
    }
    wb.water.push({ tx: c.tx, ty: c.ty, k: c.k, by: c.by, bs, until: now + WB.waterMs });
  }

  // 상자에서 나온 아이템은 위 정리가 끝난 뒤에 놓는다.
  // (같은 폭발의 물줄기가 방금 드러낸 아이템을 다시 쓸어가면 안 된다)
  for (const d of drops) wbDropItem(d[0], d[1]);
}

function wbLoopOn() { if (!wbTimer) wbTimer = setInterval(wbTick, WB.tickMs); }
function wbLoopOff() { if (wbTimer) { clearInterval(wbTimer); wbTimer = null; } }

function wbFinish(winnerId, why) {
  const order = [];
  for (const p of wb.players.values()) if (p.alive) order.push(p.id);   // 살아남은 사람 먼저
  for (const id of wb.rank) if (order.indexOf(id) < 0) order.push(id);  // 늦게 터진 순서
  for (const p of wb.players.values()) if (order.indexOf(p.id) < 0) order.push(p.id);

  wb.phase = 'done';
  wb.winner = winnerId || null;
  wb.results = order.map((id, i) => {
    const p = wb.players.get(id);
    return {
      id, rank: i + 1, name: wbName(id),
      alive: !!(p && p.alive),
      catches: p ? p.catches : 0,
      pops: p ? p.pops : 0,
      saves: p ? p.saves : 0,
    };
  });
  wbLoopOff();
  broadcast({
    t: 'sys',
    text: why || (winnerId ? `🏆 ${wbName(winnerId)} 님이 최후의 1인!` : '물풍선 — 무승부로 끝났습니다'),
  });
  sendWB();
}

function wbTick() {
  if (!wb) return wbLoopOff();
  const now = Date.now();
  const dt = WB.tickMs / 1000;

  if (wb.phase === 'countdown') {
    if (now >= wb.startAt) {
      wb.phase = 'play';
      broadcast({ t: 'sys', text: '💧 물풍선 시작!' });
    }
    sendWB();
    return;
  }
  if (wb.phase !== 'play') { wbLoopOff(); return; }

  for (const p of wb.players.values()) {
    if (!clients.has(p.id)) continue;
    wbMove(p, dt);
    if (p.ghost && !wbOverlaps(p, p.ghost.tx, p.ghost.ty)) p.ghost = null;
  }

  // 아이템 줍기
  for (let i = wb.items.length - 1; i >= 0; i--) {
    const it = wb.items[i];
    for (const p of wb.players.values()) {
      if (!p.alive || p.trapped || !clients.has(p.id)) continue;
      if (wbTileX(p.x) !== it.tx || wbTileY(p.y) !== it.ty) continue;
      if (it.k === 0) p.power = Math.min(WB.maxPower, p.power + 1);
      else if (it.k === 1) p.bombs = Math.min(WB.maxBombs, p.bombs + 1);
      else p.speed = Math.min(WB.maxSpeed, p.speed + 1);
      wb.items.splice(i, 1);
      break;
    }
  }

  // 터질 때가 된 풍선 (연쇄 때문에 목록이 바뀌므로 매번 다시 찾는다)
  for (;;) {
    const b = wb.balloons.find((x) => now - x.at >= WB.fuse);
    if (!b) break;
    wbExplode(b);
  }

  for (let i = wb.water.length - 1; i >= 0; i--) {
    if (wb.water[i].until <= now) wb.water.splice(i, 1);
  }

  // 물줄기 판정 — 발밑 한 칸만 본다 (모서리에 스쳤다고 갇히면 억울하다)
  for (const p of wb.players.values()) {
    if (!p.alive || !clients.has(p.id)) continue;
    const tx = wbTileX(p.x), ty = wbTileY(p.y);
    const hit = wb.water.find((w) => w.tx === tx && w.ty === ty);
    if (!hit) continue;
    // 물줄기는 0.7초 남아 있다. 같은 폭발이 매 틱마다 다시 판정되면
    // 가두자마자 그 물줄기가 스스로 풀어 주게 되므로 폭발당 한 번만 적용한다.
    if (hit.bs === p.lastBurst) continue;
    p.lastBurst = hit.bs;

    if (p.trapped) {
      // 갇힌 사람에게 물줄기가 닿으면 풀려난다 (누구 물줄기든)
      p.trapped = false; p.trapUntil = 0; p.safeUntil = now + WB.safeMs;
      const saver = wb.players.get(hit.by);
      if (saver && hit.by !== p.id) saver.saves++;
    } else if (now > p.safeUntil) {
      p.trapped = true;
      p.trapUntil = now + WB.trapMs;
      p.by = hit.by;
      p.input = { u: false, d: false, l: false, r: false };
      const catcher = wb.players.get(hit.by);
      if (catcher && hit.by !== p.id) catcher.catches++;
    }
  }

  // 물방울이 터지면 탈락
  for (const p of wb.players.values()) {
    if (!p.alive || !p.trapped || now < p.trapUntil) continue;
    p.alive = false; p.trapped = false;
    wb.rank.unshift(p.id);
    const killer = p.by && p.by !== p.id ? wb.players.get(p.by) : null;
    if (killer) killer.pops++;
    broadcast({
      t: 'sys',
      text: `💥 ${wbName(p.id)} 님 탈락` + (killer ? ` — ${wbName(killer.id)} 님의 물풍선` : ''),
    });
  }

  const live = [...wb.players.values()].filter((p) => p.alive && clients.has(p.id));
  if (wb.total >= 2 && live.length <= 1) {
    wbFinish(live.length === 1 ? live[0].id : null);
    return;
  }
  if (wb.total === 1 && live.length === 0) { wbFinish(null); return; }
  if (now - wb.startAt > WB.limitMs) { wbFinish(null, '⏱ 물풍선 — 제한시간 종료'); return; }

  sendWB();
}

function sendWB(only) {
  const targets = only ? [only] : [...clients.values()];

  if (!wb) {
    for (const c of targets) send(c, { t: 'wb', on: false });
    return;
  }

  const now = Date.now();
  const msg = {
    t: 'wb', on: true,
    phase: wb.phase,
    cols: WB.cols, rows: WB.rows, tile: WB.tile, ox: WB.ox, oy: WB.oy,
    fuse: WB.fuse, trapMs: WB.trapMs,
    countdown: wb.phase === 'countdown' ? Math.max(0, wb.startAt - now) : 0,
    left: wb.phase === 'play' ? Math.max(0, WB.limitMs - (now - wb.startAt)) : 0,
    players: [...wb.players.values()].filter((p) => clients.has(p.id)).map((p) => ({
      i: p.id,
      n: wbName(p.id),
      c: clients.get(p.id).color,
      x: Math.round(p.x), y: Math.round(p.y), d: p.dir,
      a: p.alive, t: p.trapped,
      tl: p.trapped ? Math.max(0, p.trapUntil - now) : 0,
      sf: p.safeUntil > now,
      pw: p.power, bm: p.bombs, sp: p.speed,
      k: p.catches, o: p.pops, v: p.saves,
    })),
    balloons: wb.balloons.map((b) => [b.tx, b.ty, Math.max(0, WB.fuse - (now - b.at))]),
    water: wb.water.map((w) => [w.tx, w.ty, w.k]),
    items: wb.items.map((it) => [it.tx, it.ty, it.k]),
    results: wb.results || null,
    winner: wb.winner || null,
  };

  // 맵은 매 틱 보낼 필요가 없다. 새로 들어온 사람, 시작 카운트다운,
  // 상자가 부서져 바뀐 틱에만 실어 보내고 클라이언트가 들고 쓴다.
  if (only || wb.mapDirty || wb.phase === 'countdown') msg.map = wb.map.join('');
  if (!only) wb.mapDirty = false;

  for (const c of targets) send(c, msg);
}

const num = (v) => (typeof v === 'number' && Number.isFinite(v) ? v : null);
const clamp = (v, lo, hi) => Math.min(hi, Math.max(lo, v));
const COLOR_RE = /^#[0-9a-fA-F]{6}$/;

const IMG_RE = /^data:image\/(png|jpeg|webp);base64,[A-Za-z0-9+/=]+$/;
const MAX_IMG_BYTES = 500 * 1024;   // 한 장 최대 크기
const MAX_CHAT_IMAGES = 12;         // 메모리에 남겨 둘 이미지 수
const MAX_CHAT_IMAGE_BYTES = 2 * 1024 * 1024;  // 새로 들어온 사람에게 한 번에 보내는 양을 제한

function cleanImage(v) {
  if (typeof v !== "string" || v.length > MAX_IMG_BYTES) return null;
  return IMG_RE.test(v) ? v : null;
}

/** 오래된 이미지는 본문만 남기고 버린다 (메모리 보호) */
function trimChatImages() {
  let seen = 0, bytes = 0;
  for (let i = chatLog.length - 1; i >= 0; i--) {
    if (!chatLog[i].image) continue;
    seen++;
    bytes += chatLog[i].image.length;
    if (seen > MAX_CHAT_IMAGES || bytes > MAX_CHAT_IMAGE_BYTES) {
      delete chatLog[i].image;
      chatLog[i].imageDropped = true;
    }
  }
}

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
    const wasTurn = bingo && bingo.order[bingo.turnIdx] === id;
    clients.delete(id);
    socket.destroy();
    broadcast({ t: 'leave', id });
    pushPeers();
    if (bingo) {
      if (wasTurn && !bingo.over) advanceTurn();  // 차례인 사람이 나가면 다음으로 넘긴다
      resetTurnDeadline();
      sendBingo();
    }
    if (liar) {
      if (liar.liarId === id && liar.phase !== 'done') {
        broadcast({ t: 'sys', text: `라이어였던 ${client.name} 님이 나가서 게임을 종료합니다 (제시어: ${liar.word})` });
        liar = null;
      } else {
        liar.votes.delete(id);
        if (liar.phase === 'vote') tallyLiar();      // 남은 사람만으로 개표가 끝날 수 있다
      }
      sendLiar();
    }
    if (arch) {
      // 나간 사람 차례였으면 다음으로 넘긴다
      if (arch.phase === 'aim' && arch.order[arch.turnIdx] === id) { nextArcher(); }
      if (![...arch.scores.keys()].some((aid) => clients.has(aid))) {
        if (arch.phase !== 'done') finishArch('참가자가 모두 나가 활쏘기를 종료합니다');
      }
      sendArch();
    }
    if (race && race.phase !== 'done' && ![...race.cars.keys()].some((cid) => clients.has(cid))) {
      endRace('참가자가 모두 나가 레이스를 종료합니다');
      sendRace();
    }
    if (wb) {
      // 나간 사람은 그 자리에서 빠진다. 남은 사람이 1명 이하가 되면 다음 틱이 정리한다.
      const p = wb.players.get(id);
      if (p) { p.alive = false; p.trapped = false; }
      if (wb.phase === 'play' && ![...wb.players.keys()].some((pid) => clients.has(pid))) {
        wbFinish(null, '참가자가 모두 나가 물풍선을 종료합니다');
      } else {
        sendWB();
      }
    }
    console.log(`[-] ${client.name} 접속 종료 (현재 ${clients.size}명)`);
  };

  send(client, {
    t: 'init',
    id,
    color: client.color,
    name: client.name,
    canvas: { w: CANVAS_W, h: CANVAS_H },
    grid: gridOn,
    raceTracks: TRACKS.map((t, i) => ({ i, name: t.name })),
    history,
    chat: chatLog,
    peers: peerList(),
  });
  pushPeers();

  // 게임 중에 들어온 사람에게도 판을 하나 주고 순번 끝에 넣는다
  if (bingo && !bingo.boards.has(id)) {
    bingo.boards.set(id, shuffledBoard(bingo.size));
    bingo.order.push(id);
  }
  sendBingo(bingo ? undefined : client);
  sendLiar(liar ? undefined : client);
  sendRace(client);   // 진행 중인 레이스는 관전만 (다음 판부터 참여)
  sendArch(client);   // 활쏘기도 마찬가지
  sendWB(client);     // 물풍선도 마찬가지

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
      // 게임 화면에도 이름이 박혀 나가므로 진행 중이면 함께 갱신한다
      if (bingo) sendBingo();
      if (liar) sendLiar();
      if (arch) sendArch();
      if (race) sendRace();
      if (wb) sendWB();
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

    case 'arch': {
      if (msg.act === 'start') {
        const ids = [...clients.keys()].sort((a, b) => a - b);
        if (!ids.length) return;

        const shotsPer = Math.round(clamp(num(msg.shots) ?? 3, 1, 10));
        const distKey = AR.dists[msg.dist] ? msg.dist : 'mid';
        const windMode = AR.winds[msg.wind] != null ? msg.wind : 'weak';
        const turnMs = Math.round(clamp(num(msg.turnMs) ?? 20000, 0, 120000));

        arch = {
          phase: 'aim',
          order: shuffleIds(ids),
          turnIdx: 0,
          shotsPer,
          targetX: AR.dists[distKey],
          windMode,
          wind: 0,
          moving: !!msg.moving,
          mvT0: Date.now(),
          turnMs, turnDeadline: 0, resumeAt: 0,
          scores: new Map(ids.map((id) => [id, { total: 0, shots: [] }])),
          arrows: [],
          shot: null, shotId: 0, results: null,
        };
        arch.wind = newWind();
        resetArchDeadline();

        broadcast({
          t: 'sys',
          text: `${client.name} 님이 활쏘기를 시작했습니다 — ${shotsPer}발씩, ${ids.length}명` +
            `${arch.moving ? ', 움직이는 과녁' : ''}`,
        });
        sendArch();
        console.log(`[=] 활쏘기 시작 — ${shotsPer}발, ${ids.length}명, 거리 ${distKey}`);
        return;
      }

      if (msg.act === 'shoot') {
        const a = num(msg.angle), pw = num(msg.power);
        if (a === null || pw === null) return;
        doShoot(client.id, a, pw, false);
        sendArch();
        return;
      }

      if (msg.act === 'end') {
        if (!arch) return;
        arch = null;
        broadcast({ t: 'sys', text: `${client.name} 님이 활쏘기를 종료했습니다` });
        sendArch();
        return;
      }
      return;
    }

    case 'wb': {
      if (msg.act === 'start') {
        const ids = [...clients.keys()].sort((a, b) => a - b);
        if (!ids.length) return;

        const picked = shuffleIds(ids).slice(0, WB_SPAWNS.length);
        const power = Math.round(clamp(num(msg.power) ?? 1, 1, WB.maxPower));
        const bombs = Math.round(clamp(num(msg.bombs) ?? 1, 1, WB.maxBombs));

        wbLoopOff();
        const now = Date.now();
        wb = {
          phase: 'countdown',
          startAt: now + 3200,
          map: wbGenMap(), mapDirty: false,
          balloons: [], water: [], items: [],
          players: new Map(), rank: [],
          burstSeq: 0,
          results: null, winner: null,
          total: picked.length,
        };
        picked.forEach((id, i) => {
          const sp = WB_SPAWNS[i];
          wb.players.set(id, {
            id, x: wbCX(sp[0]), y: wbCY(sp[1]), dir: 'd',
            alive: true, trapped: false, trapUntil: 0,
            safeUntil: now + 3600,          // 카운트다운 동안은 못 가둔다
            by: 0, ghost: null, lastBurst: 0,
            power, bombs, speed: 0,
            input: { u: false, d: false, l: false, r: false },
            catches: 0, pops: 0, saves: 0,
          });
        });

        const over = ids.length - picked.length;
        broadcast({
          t: 'sys',
          text: `${client.name} 님이 물풍선을 시작했습니다 — ${picked.length}명` +
            (over > 0 ? ` (자리가 8개라 ${over}명은 관전)` : ''),
        });
        wbLoopOn();
        sendWB();
        console.log(`[=] 물풍선 시작 — ${picked.length}명, 풍선 ${bombs} 물줄기 ${power}`);
        return;
      }

      if (msg.act === 'input') {
        if (!wb || wb.phase !== 'play') return;
        const p = wb.players.get(client.id);
        if (!p || !p.alive || p.trapped) return;
        p.input = { u: !!msg.u, d: !!msg.d, l: !!msg.l, r: !!msg.r };
        return;
      }

      if (msg.act === 'drop') {
        if (!wb || wb.phase !== 'play') return;
        const p = wb.players.get(client.id);
        if (p) wbPlace(p);
        return;
      }

      if (msg.act === 'end') {
        if (!wb) return;
        wb = null;
        wbLoopOff();
        broadcast({ t: 'sys', text: `${client.name} 님이 물풍선을 종료했습니다` });
        sendWB();
        return;
      }
      return;
    }

    case 'race': {
      if (msg.act === 'start') {
        const ids = [...clients.keys()].sort((a, b) => a - b);
        if (ids.length < 1) return;

        const laps = Math.round(clamp(num(msg.laps) ?? 3, 1, 10));
        const ti = num(msg.track);
        const pickIdx = (ti !== null && ti >= 0 && ti < TRACKS.length)
          ? Math.round(ti)
          : crypto.randomInt(TRACKS.length);          // 범위 밖이거나 미지정이면 랜덤
        const chosen = TRACKS[pickIdx];

        const now = Date.now();
        race = {
          phase: 'countdown',
          laps,
          trackIdx: pickIdx,
          trackName: chosen.name,
          track: chosen.pts,
          halfWidth: chosen.halfWidth,
          startAt: now + 3500,
          cars: new Map(),
          finishOrder: [],
          results: null,
        };
        ids.forEach((id, i) => {
          const g = gridSpot(race.track, i);
          race.cars.set(id, {
            id, x: g.x, y: g.y, a: g.a, speed: 0,
            lap: 0, cp: 0, lapStart: now, lapTimes: [], best: null,
            finished: false, finishTime: null,
            input: { u: false, d: false, l: false, r: false },
          });
        });

        broadcast({ t: 'sys', text: `${client.name} 님이 레이스를 시작했습니다 — 「${chosen.name}」 ${laps}바퀴, ${ids.length}명` });
        raceLoopOn();
        sendRace();
        console.log(`[=] 레이스 시작 — ${chosen.name}, ${laps}바퀴, ${ids.length}명`);
        return;
      }

      if (msg.act === 'input') {
        if (!race || race.phase !== 'racing') return;
        const car = race.cars.get(client.id);
        if (!car || car.finished) return;
        car.input = {
          u: !!msg.u, d: !!msg.d, l: !!msg.l, r: !!msg.r,
        };
        return;
      }

      if (msg.act === 'end') {
        if (!race) return;
        race = null;
        raceLoopOff();
        broadcast({ t: 'sys', text: `${client.name} 님이 레이스를 종료했습니다` });
        sendRace();
        return;
      }
      return;
    }

    case 'liar': {
      if (msg.act === 'start') {
        const ids = [...clients.keys()].sort((a, b) => a - b);
        if (ids.length < 3) {
          send(client, { t: 'sys', text: '라이어 게임은 3명 이상이어야 시작할 수 있습니다' });
          return;
        }
        const cats = Object.keys(LIAR_TOPICS);
        const category = cats.indexOf(msg.category) >= 0 ? msg.category : pick(cats);
        const fool = !!msg.fool;

        // 바보 라이어용 미끼 — 반드시 다른 주제에서 뽑는다
        const otherCats = cats.filter((c) => c !== category);
        const decoyCategory = pick(otherCats);

        liar = {
          phase: 'talk',
          fool,
          category,
          word: pick(LIAR_TOPICS[category]),
          decoyCategory,
          decoyWord: pick(LIAR_TOPICS[decoyCategory]),
          liarId: ids[crypto.randomInt(ids.length)],
          order: shuffleIds(ids),          // 설명하는 순서
          votes: new Map(),
          result: null,
        };

        // 바보 모드에서는 주제를 채팅에 알리지 않는다.
        // (라이어가 받은 주제와 다르면 자기가 라이어인 걸 바로 알아채기 때문)
        broadcast({
          t: 'sys',
          text: fool
            ? `${client.name} 님이 라이어 게임을 시작했습니다 — 🤪 바보 라이어 모드 (${ids.length}명) · 주제는 각자 화면에서 확인하세요`
            : `${client.name} 님이 라이어 게임을 시작했습니다 — 주제: ${category} (${ids.length}명)`,
        });
        sendLiar();
        console.log(`[=] 라이어 게임 시작 — 주제 ${category}${fool ? ' (바보 모드)' : ''}, ${ids.length}명`);
        return;
      }

      if (msg.act === 'startVote') {
        if (!liar || liar.phase !== 'talk') return;
        liar.phase = 'vote';
        liar.votes = new Map();
        broadcast({ t: 'sys', text: `${client.name} 님이 투표를 시작했습니다 — 라이어라고 생각하는 사람을 지목하세요` });
        sendLiar();
        return;
      }

      if (msg.act === 'vote') {
        if (!liar || liar.phase !== 'vote') return;
        const target = num(msg.target);
        if (target === null || !clients.has(target)) return;
        if (liar.order.indexOf(client.id) < 0) return;   // 이 판의 참가자가 아니다
        liar.votes.set(client.id, target);
        tallyLiar();
        sendLiar();
        return;
      }

      if (msg.act === 'guess') {
        if (!liar || liar.phase !== 'guess' || client.id !== liar.liarId) return;
        const raw = String(msg.text || '').trim().slice(0, 50);
        if (!raw) return;
        const correct = normalize(raw) === normalize(liar.word);
        finishLiar(!correct, { guess: raw, guessCorrect: correct });
        sendLiar();
        return;
      }

      if (msg.act === 'end') {
        if (!liar) return;
        liar = null;
        broadcast({ t: 'sys', text: `${client.name} 님이 라이어 게임을 종료했습니다` });
        sendLiar();
        return;
      }
      return;
    }

    case 'bingo': {
      if (msg.act === 'start') {
        const size = num(msg.size) === 4 ? 4 : 5;
        const maxLines = size * 2 + 2;
        const goal = Math.round(clamp(num(msg.goal) ?? 3, 1, maxLines));
        const ids = [...clients.keys()].sort((a, b) => a - b);

        // 0 이면 제한 없음
        const turnMs = Math.round(clamp(num(msg.turnMs) ?? 10000, 0, 120000));

        bingo = {
          size, goal, turnMs, turnDeadline: 0,
          // 시작할 때마다 순서를 새로 섞는다 (판 아래에서 다시 바꿀 수 있다)
          boards: new Map(), called: [], order: shuffleIds(ids), turnIdx: 0, over: false, winners: [],
        };
        for (const id of ids) bingo.boards.set(id, shuffledBoard(size));
        resetTurnDeadline();

        broadcast({ t: 'sys', text: `${client.name} 님이 빙고를 시작했습니다 — ${size}×${size} 판, ${goal}줄 완성하면 승리 (순서 무작위)` });
        sendBingo();
        console.log(`[=] ${client.name} 님이 빙고 시작 (${size}x${size}, ${goal}줄, ${ids.length}명)`);
        return;
      }

      if (msg.act === 'end') {
        if (!bingo) return;
        bingo = null;
        broadcast({ t: 'sys', text: `${client.name} 님이 빙고를 종료했습니다` });
        sendBingo();
        return;
      }

      if (msg.act === 'call') {
        if (!bingo || bingo.over) return;
        if (bingo.order[bingo.turnIdx] !== client.id) return;   // 자기 차례가 아니면 무시

        const n = num(msg.n);
        const max = bingo.size * bingo.size;
        if (n === null || n < 1 || n > max || n !== Math.round(n)) return;

        bingoCall(client.id, n, false);
        sendBingo();
        return;
      }

      if (msg.act === 'order') {
        if (!bingo) return;
        const keep = bingo.order[bingo.turnIdx];   // 차례인 사람은 그대로 유지한다

        if (msg.how === 'shuffle') {
          bingo.order = shuffleIds(bingo.order);
        } else if (msg.how === 'move') {
          const who = num(msg.id);
          const i = bingo.order.indexOf(who);
          const j = i + (msg.dir === 'up' ? -1 : 1);
          if (i < 0 || j < 0 || j >= bingo.order.length) return;
          const tmp = bingo.order[i]; bingo.order[i] = bingo.order[j]; bingo.order[j] = tmp;
        } else return;

        const at = bingo.order.indexOf(keep);
        if (at >= 0) bingo.turnIdx = at;
        broadcast({ t: "sys", text: `${client.name} 님이 빙고 순서를 바꿨습니다` });
        sendBingo();
        return;
      }
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

    case 'clearCell': {
      // 칸 나누기 중일 때, 자기 칸 안에 있는 획만 지운다
      if (!gridOn) return;
      const myArea = cellOf(client.id);
      if (!myArea) return;
      for (let i = history.length - 1; i >= 0; i--) {
        if (segInCell(history[i], myArea)) history.splice(i, 1);
      }
      broadcast({ t: "clearCell", cell: myArea, by: client.name });  // 보낸 사람에게도 전달된다
      console.log(`[!] ${client.name} 님이 자기 칸을 지웠습니다`);
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
      const image = cleanImage(msg.image);
      if (!body && !image) return;

      // @이름 / @전체 를 찾아 지목된 사람 목록을 만든다 (이름 비교는 서버가 한다)
      const mentions = [];
      const toAll = /(^|\s)@(전체|all|everyone)(\s|$)/i.test(body);
      for (const c of clients.values()) {
        if (toAll || (c.name && body.indexOf("@" + c.name) >= 0)) mentions.push(c.id);
      }

      const entry = {
        id: client.id,
        name: client.name,
        color: client.color,
        text: body,
        mentions,
        ts: Date.now(),
      };
      if (image) entry.image = image;
      chatLog.push(entry);
      if (chatLog.length > MAX_CHAT) chatLog.splice(0, chatLog.length - MAX_CHAT);
      trimChatImages();
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
