// ── 메모(낚시 게임) 함께 하기 — 웹소켓 /fish ───────────────────────
//
// memo/ 정적 사이트(youb-memo.onrender.com)의 게임이 여기에 붙는다.
// 그림판 암호와는 별개다. 다른 주소(origin)에서 오기 때문에 그림판 암호 쿠키를 쓸 수 없어서
//   (1) 허용한 주소에서 온 연결만 받고
//   (2) 같은 방 코드를 넣은 사람끼리만 만나게 한다.
// 서버가 받는 것은 별명·낚시 상태·잡은 물고기뿐이다. 메모장 내용은 오지 않는다.
// 방·기록은 메모리에만 있어서 서버가 다시 켜지면 사라진다.
'use strict';

const crypto = require('crypto');

const ORIGINS = new Set([
  'https://youb-memo.onrender.com',
  'null',                                   // 바탕화면 바로가기로 연 file:// 페이지
]);
const DEV_ORIGIN = /^http:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/;

const MAX_CONN = 400;
const MAX_ROOMS = 200;
const MAX_PER_ROOM = 8;
const MAX_MSG = 2000;          // 한 메시지 최대 글자 수
const MAX_RATE = 40;           // 초당 메시지 상한 — 넘으면 끊는다
const MIN_CATCH_MS = 3000;     // 던지기·입질·감기에 최소 이만큼은 걸린다
const CUP_COUNT_MS = 3000;     // 대회 시작 전 카운트다운
const COLORS = ['#e8553d', '#2f80ed', '#27ae60', '#f2994a', '#9b51e0', '#eb5757', '#00a3a3', '#c9a227'];
const STATES = new Set(['idle', 'charge', 'fly', 'wait', 'bite', 'reel']);

// 물고기 표 — 낚시.html 의 FISH 와 같아야 한다. [최소 cm, 최대 cm, 기준 가격]
const FISH = {
  mangdung: [8, 20, 6], jeongaeng: [15, 30, 8], godeung: [20, 40, 10],
  bollak: [12, 28, 18], noraemi: [18, 40, 20], ureok: [20, 50, 25],
  dodari: [20, 45, 45], gamseong: [25, 55, 60], gwangeo: [35, 80, 70],
  chamdom: [30, 80, 140], nongeo: [40, 100, 160], bangeo: [50, 110, 180],
  chamchi: [100, 250, 600], dotsae: [120, 300, 700],
};

// 괴물 물고기 — 방 사람들이 함께 감는 협동 이벤트
//   appear: 나타나서 합류를 받는 시간 → fight: 함께 감는 시간
//   진행도는 '초록 칸 안에 물고기를 담고 있는 사람의 비율' 로 오르내린다.
//   사람이 많을수록 빨리 차서 혼자보다 여럿이 유리하다.
const MON_KINDS = [
  { id: 'king', name: '대왕 참다랑어', diff: 1 },
  { id: 'angler', name: '심해 아귀왕', diff: 1.15 },
  { id: 'sail', name: '폭풍 돛새치', diff: 1.3 },
];
const MON_APPEAR_MS = 12000;
const MON_FIGHT_MS = 45000;
const MON_TICK_MS = 250;
const MON_START_PROG = 0.25;
const MON_NEED = 0.45;                 // 참여자 중 이 비율 이상이 칸 안에 있어야 진행도가 오른다
const MON_CALL_COOLDOWN_MS = 180000;    // 직접 부르기는 3분에 한 번
const MON_AUTO_MIN_MS = 10 * 60000;     // 2명 이상이면 10~20분마다 저절로 나타난다
const MON_AUTO_MAX_MS = 20 * 60000;

function points(id, size) {
  const f = FISH[id];
  return Math.max(1, Math.round(f[2] * size / ((f[0] + f[1]) / 2)));
}
function cleanName(v) {
  return String(v == null ? '' : v).replace(/[\u0000-\u001f<>]/g, '').replace(/\s+/g, ' ').trim().slice(0, 10);
}
function cleanRoom(v) {
  return String(v == null ? '' : v).toLowerCase().replace(/[^0-9a-z가-힣_-]/g, '').slice(0, 20);
}

module.exports = function makeFish({ encodeFrame, feed, GUID }) {
  const rooms = new Map();     // 방 코드 → { code, players: Map, cup, timers }
  let conns = 0;
  let nextId = 1;

  const frameOf = (obj) => encodeFrame(0x1, Buffer.from(JSON.stringify(obj), 'utf8'));
  function write(p, frame) {
    if (p.socket.destroyed) return;
    try { p.socket.write(frame); } catch { /* 끊긴 소켓 */ }
  }
  function sendTo(p, obj) { write(p, frameOf(obj)); }
  function broadcast(room, obj, exceptId) {
    const frame = frameOf(obj);
    for (const p of room.players.values()) if (p.id !== exceptId) write(p, frame);
  }

  function pView(p) {
    return { i: p.id, n: p.name, c: p.color, s: p.slot, st: p.st, a: p.away, h: p.haul, b: p.best };
  }
  function cupView(room) {
    const c = room.cup;
    if (!c) return null;
    const now = Date.now();
    const rows = [...c.scores.values()]
      .sort((a, b) => b.pts - a.pts || a.at - b.at)
      .map((r) => ({ i: r.id, n: r.name, c: r.color, pts: r.pts, cnt: r.count, best: r.best }));
    const left = c.phase === 'count' ? c.startAt - now : c.phase === 'run' ? c.endAt - now : 0;
    return { ph: c.phase, mins: c.mins, left: Math.max(0, left), rows, by: c.by };
  }
  function sendRoom(room) {
    const players = [...room.players.values()].map(pView);
    const cup = cupView(room);
    const mon = monView(room);
    for (const p of room.players.values()) sendTo(p, { t: 'room', you: p.id, code: room.code, players, cup, mon });
  }

  function join(me, m) {
    const code = cleanRoom(m.room);
    const name = cleanName(m.name);
    if (!code || !name) return sendTo(me, { t: 'err', m: '별명과 방 코드를 넣어 주세요' });
    if (me.room) leave(me);

    let room = rooms.get(code);
    if (!room) {
      if (rooms.size >= MAX_ROOMS) return sendTo(me, { t: 'err', m: '지금은 방을 더 만들 수 없어요' });
      room = { code, players: new Map(), cup: null, timers: [], gone: new Map(), mon: null, monTick: null, monNext: null, monLastCall: 0 };
      rooms.set(code, room);
    }
    if (room.players.size >= MAX_PER_ROOM) return sendTo(me, { t: 'err', m: '방이 가득 찼어요 (최대 8명)' });

    const used = new Set([...room.players.values()].map((p) => p.slot));
    let slot = 0;
    while (used.has(slot)) slot++;
    Object.assign(me, { room, name, slot, color: COLORS[slot], st: 'idle', away: false, haul: 0, best: null, lastCatch: 0 });
    room.players.set(me.id, me);

    // 연결이 잠깐 끊겼다 같은 별명으로 다시 들어온 사람은 기록을 이어받는다 (10분 안)
    const g = room.gone.get(name);
    if (g && Date.now() - g.at < 10 * 60000) { me.haul = g.haul; me.best = g.best; room.gone.delete(name); }
    const c = room.cup;
    if (c && c.phase !== 'done') {
      for (const [oldId, r] of c.scores) {
        if (r.name === name && oldId !== me.id && !room.players.has(oldId)) {
          c.scores.delete(oldId);
          r.id = me.id; r.color = me.color;
          c.scores.set(me.id, r);
          break;
        }
      }
    }
    sendRoom(room);
    monSchedule(room);
  }

  function leave(me, tell) {
    const room = me.room;
    if (!room) return;
    room.players.delete(me.id);
    me.room = null;
    if (me.haul || me.best) room.gone.set(me.name, { haul: me.haul, best: me.best, at: Date.now() });
    if (room.mon) { room.mon.joined.delete(me.id); room.mon.inz.delete(me.id); }
    if (!room.players.size) {
      room.timers.forEach(clearTimeout);
      monClear(room);
      rooms.delete(room.code);
    } else {
      sendRoom(room);
      if (room.players.size < 2) { clearTimeout(room.monNext); room.monNext = null; }
    }
    if (tell) sendTo(me, { t: 'left' });
  }

  function setState(me, m) {
    if (!me.room) return;
    const st = STATES.has(m.st) ? m.st : me.st;
    const away = !!m.a;
    if (st === me.st && away === me.away) return;
    me.st = st;
    me.away = away;
    if (away && me.room.mon) me.room.mon.inz.delete(me.id);   // 메모장 보는 동안은 감는 것으로 치지 않는다
    broadcast(me.room, { t: 'p', i: me.id, st, a: away }, me.id);
  }

  function onCatch(me, m) {
    const room = me.room;
    if (!room) return;
    const f = FISH[m.f];
    const size = Number(m.size);
    if (!f || !Number.isFinite(size) || size < f[0] - 0.05 || size > f[1] + 0.05) return;
    const now = Date.now();
    if (now - me.lastCatch < MIN_CATCH_MS) return;      // 너무 빠른 연속 보고는 무시
    me.lastCatch = now;

    const sz = Math.round(size * 10) / 10;
    const pts = points(m.f, sz);                        // 점수는 서버가 계산한다
    me.haul += pts;
    if (!me.best || pts > me.best.pts) me.best = { f: m.f, size: sz, pts };

    let inCup = false;
    const c = room.cup;
    if (c && c.phase === 'run' && now < c.endAt) {
      let r = c.scores.get(me.id);
      if (!r) {
        r = { id: me.id, name: me.name, color: me.color, pts: 0, count: 0, best: null, at: now };
        c.scores.set(me.id, r);
      }
      r.pts += pts; r.count++; r.at = now;
      if (!r.best || pts > r.best.pts) r.best = { f: m.f, size: sz, pts };
      inCup = true;
    }
    broadcast(room, {
      t: 'got', i: me.id, n: me.name, f: m.f, size: sz, pts,
      h: me.haul, b: me.best, cup: inCup ? cupView(room) : undefined,
    });
  }

  function cupStart(me, m) {
    const room = me.room;
    if (!room) return;
    if (room.cup && (room.cup.phase === 'count' || room.cup.phase === 'run')) return;
    if (room.mon) return sendTo(me, { t: 'note', m: '괴물 물고기와 싸우는 중이라 대회를 열 수 없어요' });
    const mins = m.mins === 5 ? 5 : 3;
    const now = Date.now();
    const scores = new Map();
    for (const p of room.players.values()) {
      scores.set(p.id, { id: p.id, name: p.name, color: p.color, pts: 0, count: 0, best: null, at: now });
    }
    room.cup = {
      phase: 'count', mins, by: me.name, scores,
      startAt: now + CUP_COUNT_MS,
      endAt: now + CUP_COUNT_MS + mins * 60000,
    };
    room.timers.forEach(clearTimeout);
    room.timers = [
      setTimeout(() => {
        if (!room.cup) return;
        room.cup.phase = 'run';
        broadcast(room, { t: 'cup', cup: cupView(room) });
      }, CUP_COUNT_MS),
      setTimeout(() => {
        if (!room.cup) return;
        room.cup.phase = 'done';
        broadcast(room, { t: 'cup', cup: cupView(room) });
      }, CUP_COUNT_MS + mins * 60000),
    ];
    broadcast(room, { t: 'cup', cup: cupView(room) });
  }

  // ── 괴물 물고기 ──
  function cupRunning(room) { return !!(room.cup && (room.cup.phase === 'count' || room.cup.phase === 'run')); }
  function monView(room) {
    const m = room.mon;
    if (!m) return null;
    return {
      id: m.id, kind: m.kind.id, name: m.kind.name, ph: m.ph,
      left: Math.max(0, m.endAt - Date.now()),
      prog: Math.round(m.prog * 1000) / 1000,
      joined: [...m.joined], inz: [...m.inz],
    };
  }
  function monClear(room) {
    clearInterval(room.monTick); room.monTick = null;
    clearTimeout(room.monNext); room.monNext = null;
    room.mon = null;
  }
  function monSchedule(room) {
    if (room.monNext || room.mon || room.players.size < 2) return;
    const wait = MON_AUTO_MIN_MS + Math.random() * (MON_AUTO_MAX_MS - MON_AUTO_MIN_MS);
    room.monNext = setTimeout(() => {
      room.monNext = null;
      if (!rooms.has(room.code)) return;
      if (room.players.size >= 2 && !room.mon && !cupRunning(room)) monStart(room, null);
      else monSchedule(room);
    }, wait);
  }
  let monSeq = 0;
  function monStart(room, by) {
    const kind = MON_KINDS[Math.floor(Math.random() * MON_KINDS.length)];
    clearTimeout(room.monNext); room.monNext = null;
    room.mon = {
      id: ++monSeq, kind, ph: 'appear', prog: MON_START_PROG,
      endAt: Date.now() + MON_APPEAR_MS, joined: new Set(), inz: new Set(),
    };
    broadcast(room, { t: 'mon', mon: monView(room), by: by || '' });
    room.monTick = setInterval(() => monStep(room), MON_TICK_MS);
  }
  function monStep(room) {
    const m = room.mon;
    if (!m) return;
    const now = Date.now();
    for (const id of m.joined) if (!room.players.has(id)) { m.joined.delete(id); m.inz.delete(id); }
    if (m.ph === 'appear') {
      if (now >= m.endAt) {
        if (!m.joined.size) return monEnd(room, 'gone');
        m.ph = 'fight';
        m.endAt = now + MON_FIGHT_MS;
      }
      broadcast(room, { t: 'mon', mon: monView(room) });
      return;
    }
    const k = m.joined.size;
    if (!k) return monEnd(room, 'lose');
    const f = m.inz.size / k;
    const rate = (0.10 + 0.025 * (k - 1)) / m.kind.diff;     // 사람이 많을수록 빨리 찬다
    m.prog += rate * (f - MON_NEED) * (MON_TICK_MS / 1000);
    if (m.prog >= 1) return monEnd(room, 'win');
    if (m.prog <= 0 || now >= m.endAt) return monEnd(room, 'lose');
    broadcast(room, { t: 'mon', mon: monView(room) });
  }
  function monEnd(room, result) {
    const m = room.mon;
    const view = monView(room);
    view.ph = result;
    view.prog = result === 'win' ? 1 : Math.max(0, view.prog);
    view.names = [...m.joined].map((id) => (room.players.get(id) || {}).name).filter(Boolean);
    view.reward = result === 'win' ? Math.round((200 + 80 * m.joined.size) * m.kind.diff) : 0;
    clearInterval(room.monTick); room.monTick = null;
    room.mon = null;
    broadcast(room, { t: 'mon', mon: view });
    monSchedule(room);
  }
  function monCall(me) {
    const room = me.room;
    if (!room) return;
    const now = Date.now();
    if (room.mon) return sendTo(me, { t: 'note', m: '이미 괴물이 나와 있어요' });
    if (cupRunning(room)) return sendTo(me, { t: 'note', m: '대회 중에는 부를 수 없어요' });
    const wait = room.monLastCall + MON_CALL_COOLDOWN_MS - now;
    if (wait > 0) return sendTo(me, { t: 'note', m: '괴물은 3분에 한 번만 부를 수 있어요 (' + Math.ceil(wait / 1000) + '초 남음)' });
    room.monLastCall = now;
    monStart(room, me.name);
  }
  function monJoin(me) {
    const m = me.room && me.room.mon;
    if (!m || me.away || (m.ph !== 'appear' && m.ph !== 'fight')) return;
    m.joined.add(me.id);
    broadcast(me.room, { t: 'mon', mon: monView(me.room) });
  }
  function monIn(me, v) {
    const m = me.room && me.room.mon;
    if (!m || !m.joined.has(me.id)) return;
    if (v && !me.away) m.inz.add(me.id); else m.inz.delete(me.id);
  }
  function monOut(me) {
    const m = me.room && me.room.mon;
    if (!m) return;
    m.joined.delete(me.id); m.inz.delete(me.id);
  }

  function onMsg(me, text, close) {
    const now = Date.now();
    if (now - me.rateT > 1000) { me.rateT = now; me.rateN = 0; }
    if (++me.rateN > MAX_RATE || text.length > MAX_MSG) return close();
    let m;
    try { m = JSON.parse(text); } catch { return; }
    if (!m || typeof m !== 'object') return;
    switch (m.t) {
      case 'join': return join(me, m);
      case 'leave': return leave(me, true);
      case 'st': return setState(me, m);
      case 'catch': return onCatch(me, m);
      case 'cup': return cupStart(me, m);
      case 'monCall': return monCall(me);
      case 'monJoin': return monJoin(me);
      case 'monIn': return monIn(me, !!m.v);
      case 'monOut': return monOut(me);
      default: return;            // ping 등은 그냥 받기만 한다 (연결 유지용)
    }
  }

  function upgrade(req, socket) {
    const key = req.headers['sec-websocket-key'];
    const origin = req.headers.origin || '';
    if (!key || !(ORIGINS.has(origin) || DEV_ORIGIN.test(origin))) {
      socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
      return socket.destroy();
    }
    if (conns >= MAX_CONN) {
      socket.write('HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n');
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
    conns++;

    const me = {
      id: nextId++, socket, room: null, name: '', color: '', slot: -1,
      st: 'idle', away: false, haul: 0, best: null, lastCatch: 0, rateT: 0, rateN: 0,
      state: { buf: Buffer.alloc(0), frag: null, fragOp: 0 },
    };
    let closed = false;
    const close = () => {
      if (closed) return;
      closed = true;
      conns--;
      leave(me);
      try { socket.destroy(); } catch { /* 이미 닫힘 */ }
    };
    socket.on('data', (chunk) => {
      feed(me.state, chunk, {
        close,
        pong: (payload) => socket.write(encodeFrame(0xA, payload)),
        message: (text) => onMsg(me, text, close),
      });
    });
    socket.on('error', close);
    socket.on('close', close);
  }

  return { upgrade, stats: () => ({ rooms: rooms.size, conns }) };
};
