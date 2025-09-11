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

// Default fallback
router.all('*', () => new Response('Not Found', { status: 404 }));

// Worker entry point
export default {
  async fetch(request, env, ctx) {
    return router.handle(request, env, ctx);
  }
};
