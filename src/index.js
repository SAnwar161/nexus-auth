import { Router } from 'itty-router';
import { verifyJWT } from './lib/jwt'; // Adjust path if needed

const router = Router();

// GET /auth/me — returns email and plan
router.get('/auth/me', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token);
  if (!user || !user.id) {
    return new Response('Invalid token', { status: 403 });
  }

  const result = await ctx.env.DB.prepare(`
    SELECT email, plan FROM users WHERE id = ?
  `).bind(user.id).first();

  if (!result) {
    return new Response('User not found', { status: 404 });
  }

  return new Response(JSON.stringify(result), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// POST /auth/upgrade — changes user's plan
router.post('/auth/upgrade', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token);
  if (!user || !user.id) {
    return new Response('Invalid token', { status: 403 });
  }

  const { newPlan } = await ctx.request.json();
  const allowedPlans = ['starter', 'pro', 'team'];
  if (!allowedPlans.includes(newPlan)) {
    return new Response('Invalid plan', { status: 400 });
  }

  await ctx.env.DB.prepare(`
    UPDATE users SET plan = ? WHERE id = ?
  `).bind(newPlan, user.id).run();

  return new Response(JSON.stringify({ success: true, plan: newPlan }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// POST /analytics/track — logs user events
router.post('/analytics/track', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token);
  if (!user || !user.id) {
    return new Response('Invalid token', { status: 403 });
  }

  const { event, metadata } = await ctx.request.json();
  const timestamp = new Date().toISOString();

  await ctx.env.DB.prepare(`
    INSERT INTO analytics (user_id, event, metadata, timestamp)
    VALUES (?, ?, ?, ?)
  `).bind(user.id, event, JSON.stringify(metadata || {}), timestamp).run();

  return new Response('Event tracked', {
    status: 200,
    headers: { 'Content-Type': 'application/json' }
  });
});

// GET /admin/overview — returns user and event data for admin
router.get('/admin/overview', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token);
  if (!user || !user.id || user.email !== 'sadat@nexuschats.com') {
    return new Response('Forbidden', { status: 403 });
  }

  const users = await ctx.env.DB.prepare(`
    SELECT email, plan, created_at FROM users ORDER BY created_at DESC
  `).all();

  const events = await ctx.env.DB.prepare(`
    SELECT event, metadata, timestamp FROM analytics ORDER BY timestamp DESC LIMIT 100
  `).all();

  return new Response(JSON.stringify({ users: users.results, events: events.results }), {
    headers: { 'Content-Type': 'application/json' }
  });
});

// POST /admin/send-email — sends automated email to a user
router.post('/admin/send-email', async (ctx) => {
  const authHeader = ctx.request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
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
router.all('*', () => new Response('Not Found', { status: 404 }));

// Worker entry point
export default {
  async fetch(request, env, ctx) {
    return router.handle(request, env, ctx);
  }
};
