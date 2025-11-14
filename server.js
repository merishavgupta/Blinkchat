// server.js
require('dotenv').config();
const express = require('express');
const http = require('http');
const helmet = require('helmet');
const cors = require('cors');
const { Server } = require('socket.io');
const Filter = require('bad-words');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

const app = express();
app.use(helmet());
app.use(cors());
app.use(express.json());

// CONFIG - change environment vars on hosting panel if needed
const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'change_admin_token_here';
const SITE_NAME = process.env.SITE_NAME || 'BlinkChat';

// Moderation/config
const MAX_STRIKES = 3;
const SUSPEND_MS = 1000 * 60 * 60; // 1 hour
const SESSION_MAX_MS = 1000 * 60 * 60; // 60 min
const RATE_LIMIT_MSGS_PER_10S = 20;
const RATE_LIMIT_WINDOW_MS = 10 * 1000;

const queue = [];
const sockets = new Map();
const pairs = new Map();
const reports = [];
const moderationLog = [];

const filter = new Filter();
// Add more explicit words for production (English + Hindi) to this list
filter.addWords('explicitword1','explicitword2','porn','sex','nude','xxx');

const phoneRegex = /(\+?\d{10,15})|(\d{3}[-.\s]\d{3}[-.\s]\d{4})/;
const emailRegex = /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/;
const urlRegex = /(https?:\/\/[^\s]+)/i;

function sendSystem(socket, text) {
  try { socket.emit('system', text); } catch(e) {}
}

function moderateText(text) {
  if (!text || typeof text !== 'string') return { ok: false, reason: 'invalid' };
  if (filter.isProfane(text)) return { ok: false, reason: 'profanity' };
  if (phoneRegex.test(text) || emailRegex.test(text) || urlRegex.test(text)) return { ok: false, reason: 'pii_or_link' };
  return { ok: true };
}

function createRateTracker() { return { timestamps: [] }; }
function allowMessage(rateTracker) {
  const now = Date.now();
  rateTracker.timestamps = rateTracker.timestamps.filter(t => (now - t) <= RATE_LIMIT_WINDOW_MS);
  if (rateTracker.timestamps.length >= RATE_LIMIT_MSGS_PER_10S) return false;
  rateTracker.timestamps.push(now);
  return true;
}

// Matchmaking
function tryMatch(socketId) {
  while (queue.length > 0) {
    const candidate = queue.shift();
    if (!sockets.has(candidate.id)) continue;
    const s = sockets.get(candidate.id);
    if (s.partnerId || (s.suspendedUntil && s.suspendedUntil > Date.now())) continue;
    if (candidate.id === socketId) {
      queue.unshift(candidate);
      return null;
    }
    // pair
    pairs.set(socketId, candidate.id);
    pairs.set(candidate.id, socketId);
    const sa = sockets.get(socketId);
    const sb = sockets.get(candidate.id);
    sa.partnerId = candidate.id;
    sb.partnerId = socketId;
    const sockA = io.sockets.sockets.get(socketId);
    const sockB = io.sockets.sockets.get(candidate.id);
    if (sockA) sockA.emit('partnerFound', { id: candidate.id, gender: sb.gender || '' });
    if (sockB) sockB.emit('partnerFound', { id: socketId, gender: sa.gender || '' });
    moderationLog.push({ action: 'pair', a: socketId, b: candidate.id, ts: Date.now() });
    return { a: socketId, b: candidate.id };
  }
  if (!queue.find(q => q.id === socketId)) queue.push({ id: socketId });
  return null;
}

function disconnectPartner(socketId, reason = 'left') {
  const partnerId = pairs.get(socketId);
  if (!partnerId) return;
  pairs.delete(socketId);
  pairs.delete(partnerId);
  const s = sockets.get(socketId); if (s) s.partnerId = null;
  const p = sockets.get(partnerId); if (p) p.partnerId = null;
  const sockP = io.sockets.sockets.get(partnerId);
  if (sockP) {
    sockP.emit('partnerDisconnected', { reason });
    tryMatch(partnerId);
  }
}

// Serve frontend static files from /public
app.use(express.static(path.join(__dirname, 'public')));

// Admin endpoints (simple)
app.get('/admin/reports', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  res.json({ reports, moderationLog, queueSize: queue.length, activeSockets: sockets.size });
});

app.post('/admin/action/suspend', (req, res) => {
  const token = req.headers['x-admin-token'];
  if (!token || token !== ADMIN_TOKEN) return res.status(401).json({ error: 'unauthorized' });
  const { socketId, ms } = req.body;
  if (!socketId || !sockets.has(socketId)) return res.status(400).json({ error: 'invalid_socket' });
  const meta = sockets.get(socketId);
  meta.suspendedUntil = Date.now() + (ms || SUSPEND_MS);
  moderationLog.push({ action: 'admin_suspend', socketId, ms, ts: Date.now() });
  const sock = io.sockets.sockets.get(socketId);
  if (sock) sock.emit('system', 'You have been suspended by admins.');
  res.json({ ok: true });
});

app.get('/api/site-info', (req, res) => {
  res.json({ name: SITE_NAME, description: `${SITE_NAME} - anonymous friendly chat` });
});

// Start server + socket.io
const server = http.createServer(app);
const io = new Server(server, {
  cors: { origin: process.env.FRONTEND_ORIGIN === '*' ? '*' : (process.env.FRONTEND_ORIGIN || '*'), methods: ['GET','POST'] },
});

io.on('connection', (socket) => {
  sockets.set(socket.id, {
    username: null,
    gender: null,
    partnerId: null,
    strikes: 0,
    suspendedUntil: 0,
    rate: createRateTracker(),
    connectedAt: Date.now(),
    sessionTimer: null
  });

  socket.on('join', (payload) => {
    const meta = sockets.get(socket.id);
    if (!meta) return;
    meta.username = payload && payload.username ? String(payload.username).slice(0, 50) : `anon_${socket.id.slice(0,6)}`;
    meta.gender = payload && payload.gender ? String(payload.gender).slice(0,20) : '';
    if (meta.suspendedUntil && meta.suspendedUntil > Date.now()) {
      sendSystem(socket, 'You are suspended due to policy violations.');
      socket.disconnect(true);
      return;
    }
    tryMatch(socket.id);
    meta.sessionTimer = setTimeout(() => {
      sendSystem(socket, 'Session time limit reached. Disconnecting.');
      disconnectPartner(socket.id, 'session_timeout');
      socket.disconnect(true);
    }, SESSION_MAX_MS);
  });

  socket.on('message', (data) => {
    const meta = sockets.get(socket.id);
    if (!meta) return;
    if (!allowMessage(meta.rate)) {
      meta.strikes += 1;
      moderationLog.push({ action: 'rate_limit', socket: socket.id, strikes: meta.strikes, ts: Date.now() });
      sendSystem(socket, 'You are sending messages too quickly. Slow down.');
      if (meta.strikes >= MAX_STRIKES) {
        meta.suspendedUntil = Date.now() + SUSPEND_MS;
        sendSystem(socket, 'You have been suspended for repeated infractions.');
        socket.disconnect(true);
      }
      return;
    }

    const text = data && data.message ? String(data.message).slice(0, 2000) : '';
    const m = moderateText(text);
    if (!m.ok) {
      meta.strikes += 1;
      moderationLog.push({ action: 'moderation_block', socket: socket.id, reason: m.reason, text: text.slice(0,200), ts: Date.now() });
      sendSystem(socket, 'Your message was blocked due to policy violation.');
      const partnerId = meta.partnerId;
      if (partnerId) {
        const partnerSock = io.sockets.sockets.get(partnerId);
        if (partnerSock) partnerSock.emit('system', 'A message from partner was blocked by moderation.');
      }
      if (meta.strikes >= MAX_STRIKES) {
        meta.suspendedUntil = Date.now() + SUSPEND_MS;
        moderationLog.push({ action: 'suspend_auto', socket: socket.id, ts: Date.now() });
        const partner = meta.partnerId;
        if (partner) {
          const partnerSock = io.sockets.sockets.get(partner);
          if (partnerSock) {
            partnerSock.emit('system', 'Your partner was suspended. You will be re-matched shortly.');
            disconnectPartner(partner);
          }
        }
        socket.disconnect(true);
      }
      return;
    }

    const partnerId = meta.partnerId;
    if (!partnerId) {
      sendSystem(socket, 'No partner connected yet. Try Next Person.');
      return;
    }
    const partnerSock = io.sockets.sockets.get(partnerId);
    if (!partnerSock) {
      sendSystem(socket, 'Partner disconnected. Searching for new partner...');
      meta.partnerId = null;
      tryMatch(socket.id);
      return;
    }
    partnerSock.emit('message', { message: text, from: socket.id });
    socket.emit('messageAck', { ok: true });
  });

  socket.on('typing', () => {
    const meta = sockets.get(socket.id);
    if (!meta) return;
    const partnerId = meta.partnerId;
    if (!partnerId) return;
    const partnerSock = io.sockets.sockets.get(partnerId);
    if (!partnerSock) return;
    partnerSock.emit('typing', { from: socket.id });
  });

  socket.on('nextPerson', () => {
    const meta = sockets.get(socket.id);
    if (!meta) return;
    const oldPartner = meta.partnerId;
    if (oldPartner) {
      const oldSock = io.sockets.sockets.get(oldPartner);
      if (oldSock) {
        oldSock.emit('system', 'Your partner left the chat.');
        const oldMeta = sockets.get(oldPartner);
        if (oldMeta) { oldMeta.partnerId = null; tryMatch(oldPartner); }
      }
      pairs.delete(socket.id);
      pairs.delete(oldPartner);
      meta.partnerId = null;
    }
    tryMatch(socket.id);
  });

  socket.on('report', (payload) => {
    const meta = sockets.get(socket.id);
    if (!meta) return;
    const partner = meta.partnerId;
    const reason = payload && payload.reason ? String(payload.reason).slice(0,200) : 'reported';
    const rpt = { id: uuidv4(), reporter: socket.id, reported: partner || null, reason, ts: Date.now() };
    reports.push(rpt);
    moderationLog.push({ action: 'report', ...rpt });
    sendSystem(socket, 'Report received. Moderation will review.');
    if (partner) {
      const reportedMeta = sockets.get(partner);
      if (reportedMeta) {
        reportedMeta.suspendedUntil = Date.now() + (5 * 60 * 1000); // temp 5 min hold
        const reportedSock = io.sockets.sockets.get(partner);
        if (reportedSock) reportedSock.emit('system', 'You have been flagged for review and may be temporarily suspended.');
        disconnectPartner(partner, 'reported');
      }
    }
  });

  socket.on('disconnect', (reason) => {
    const meta = sockets.get(socket.id);
    if (meta && meta.sessionTimer) clearTimeout(meta.sessionTimer);
    const partnerId = pairs.get(socket.id);
    if (partnerId) {
      const partnerSock = io.sockets.sockets.get(partnerId);
      if (partnerSock) partnerSock.emit('system', 'Your partner disconnected.');
      pairs.delete(partnerId);
      pairs.delete(socket.id);
      const partnerMeta = sockets.get(partnerId);
      if (partnerMeta) partnerMeta.partnerId = null;
      tryMatch(partnerId);
    }
    const qidx = queue.findIndex(q => q.id === socket.id);
    if (qidx >= 0) queue.splice(qidx, 1);
    sockets.delete(socket.id);
    moderationLog.push({ action: 'disconnect', socket: socket.id, reason, ts: Date.now() });
  });
});

server.listen(PORT, () => {
  console.log(`${SITE_NAME} server running on port ${PORT}`);
});