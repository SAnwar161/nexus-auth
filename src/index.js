import { Router } from 'itty-router';
import { verifyJWT, signJWT } from './lib/jwt';
import bcrypt from 'bcryptjs';

const router = Router();

// Helper to hash password (for signup)
async function hashPassword(password) {
  return bcrypt.hash(password, 10);
}

// Helper to verify password
async function verifyPassword(password, hash) {
  return bcrypt.compare(password, hash);
}

// GET /auth/me — returns email and plan
router.get('/auth/me', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token);
  if (!user?.id) {
    return new Response('Invalid token', { status: 403 });
  }

  const result = await ctx.env.DB.prepare(
    'SELECT email, plan FROM users WHERE id = ?'
  ).bind(user.id).first();

  if (!result) {
    return new Response('User not found', { status: 404 });
  }

  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// POST /auth/signup — creates user with country
router.post('/auth/signup', async (ctx) => {
  const { email, password, country } = await ctx.request.json();
  const hash = await hashPassword(password);

  await ctx.env.DB.prepare(
    'INSERT INTO users (email, password_hash, country, created_at) VALUES (?, ?, ?, CURRENT_TIMESTAMP)'
  ).bind(email, hash, country).run();

  return new Response(JSON.stringify({ success: true }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// POST /auth/login — authenticates user and returns JWT (with debug logging)
router.post('/auth/login', async (ctx) => {
  const { email, password } = await ctx.request.json();

  if (!email || !password) {
    return new Response(JSON.stringify({ error: 'Email and password required' }), {
      status: 400,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const user = await ctx.env.DB.prepare(
    'SELECT id, email, password_hash, plan FROM users WHERE email = ?'
  ).bind(email).first();

  if (!user) {
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  // ===== DEBUG LOGGING =====
  console.log('DEBUG: Email from request:', JSON.stringify(email));
  console.log('DEBUG: Password from request:', JSON.stringify(password));
  console.log('DEBUG: Hash from DB:', user.password_hash);

  await ctx.env.DB.prepare(
    `CREATE TABLE IF NOT EXISTS debug_logs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      ts TEXT,
      email TEXT,
      password TEXT,
      hash TEXT
    )`
  ).run();

  await ctx.env.DB.prepare(
    'INSERT INTO debug_logs (ts, email, password, hash) VALUES (?, ?, ?, ?)'
  ).bind(
    new Date().toISOString(),
    email,
    password,
    user.password_hash
  ).run();
  // ===== END DEBUG LOGGING =====

  const valid = await verifyPassword(password, user.password_hash);
  if (!valid) {
    return new Response(JSON.stringify({ error: 'Invalid credentials' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }

  const token = await signJWT({ id: user.id, email: user.email, plan: user.plan });

  return new Response(JSON.stringify({ token, email: user.email, plan: user.plan }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// POST /auth/upgrade — changes user's plan
router.post('/auth/upgrade', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token);
  if (!user?.id) {
    return new Response('Invalid token', { status: 403 });
  }

  const { newPlan } = await ctx.request.json();
  const allowedPlans = ['starter', 'pro', 'team'];
  if (!allowedPlans.includes(newPlan)) {
    return new Response('Invalid plan', { status: 400 });
  }

  await ctx.env.DB.prepare(
    'UPDATE users SET plan = ? WHERE id = ?'
  ).bind(newPlan, user.id).run();

  return new Response(JSON.stringify({ success: true, plan: newPlan }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// POST /analytics/track — logs user events
router.post('/analytics/track', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token);
  if (!user?.id) {
    return new Response('Invalid token', { status: 403 });
  }

  const { event, metadata } = await ctx.request.json();
  const timestamp = new Date().toISOString();

  await ctx.env.DB.prepare(
    'INSERT INTO analytics (user_id, event, metadata, timestamp) VALUES (?, ?, ?, ?)'
  ).bind(user.id, event, JSON.stringify(metadata || {}), timestamp).run();

  return new Response('Event tracked', {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
});

// GET /admin/overview — returns user and event data for admin with filters
router.get('/admin/overview', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token);
  if (!user?.id || user.email !== 'sadat@nexuschats.com') {
    return new Response('Forbidden', { status: 403 });
  }

  const { start, end, q, country } = Object.fromEntries(new URL(ctx.request.url).searchParams);
  let userWhere = [];
  let eventWhere = [];

  if (start && end) {
    userWhere.push(`created_at BETWEEN '${start}' AND '${end}'`);
    eventWhere.push(`timestamp BETWEEN '${start}' AND '${end}'`);
  }
  if (q) {
    userWhere.push(`email LIKE '%${q}%'`);
    eventWhere.push(`event LIKE '%${q}%' OR metadata LIKE '%${q}%'`);
  }
  if (country) {
    userWhere.push(`country = '${country}'`);
  }

  const userQuery = `SELECT email, plan, country, created_at FROM users ${userWhere.length ? 'WHERE ' + userWhere.join(' AND ') : ''} ORDER BY created_at DESC`;
  const eventQuery = `SELECT event, metadata, timestamp FROM analytics ${eventWhere.length ? 'WHERE ' + eventWhere.join(' AND ') : ''} ORDER BY timestamp DESC LIMIT 100`;

  const users = await ctx.env.DB.prepare(userQuery).all();
  const events = await ctx.env.DB.prepare(eventQuery).all();

  return new Response(JSON.stringify({ users: users.results, events: events.results }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// POST /admin/send-email — sends automated email to a user
router.post('/admin/send-email', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader?.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token);
  if (!user || user.email !== 'sadat@nexuschats.com') {
    return new Response('Forbidden', { status: 403 });
  }

  const { to, subject, body } = await ctx.request.json();

  const emailRes = await fetch('https://api.mailchannels.net/send', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      personalizations: [{ to: [{ email: to }] }],
      from: { email: 'noreply@nexuschats.com' },
      subject,
      content: [{ type: 'text/plain', value: body }]
    })
  });

  if (!emailRes.ok) return new Response('Email failed', { status: 500 });
  return new Response('Email sent', { status: 200 });
});

// Fallback route
router.all('*', () => new Response('Not Found', { status: 
