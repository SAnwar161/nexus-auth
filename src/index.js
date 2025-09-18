import { Router } from 'itty-router';
import { signJWT, verifyJWT } from './jwt';
import bcrypt from 'bcryptjs';

const router = Router();

router.post('/auth/login', async (request, env, ctx) => {
  const { email, password } = await request.json();
  const user = await env.DB.prepare('SELECT * FROM users WHERE email = ?').bind(email).first();

  if (!user) {
    console.log('❌ No user found for:', email);
    return new Response('Unauthorized', { status: 401 });
  }

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) {
    console.log('❌ Invalid password for:', email);
    return new Response('Unauthorized', { status: 401 });
  }

  const token = await signJWT(
    { id: user.id, email: user.email, plan: user.plan },
    ctx.env.JWT_SECRET
  );

  console.log('✅ JWT signed for:', email);
  return new Response(JSON.stringify({ token }), {
    headers: { 'Content-Type': 'application/json' },
  });
});

<<<<<<< HEAD
// Fallback route
router.all('*', () => new Response('Not Found', { status: 404 }));

export default {
  fetch: (request, env, ctx) => router.handle(request, env, ctx)
};
=======
router.post('/auth/me', async (request, env, ctx) => {
  const { token } = await request.json();
  try {
    const user = await verifyJWT(token, ctx.env.JWT_SECRET);
    return new Response(JSON.stringify({ user }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.log('⚠️ JWT verification failed:', err.message);
    return new Response('Unauthorized', { status: 401 });
  }
});

router.post('/auth/upgrade', async (request, env, ctx) => {
  const { token } = await request.json();
  try {
    const user = await verifyJWT(token, ctx.env.JWT_SECRET);
    await env.DB.prepare('UPDATE users SET plan = ? WHERE id = ?')
      .bind('pro', user.id)
      .run();

    return new Response(JSON.stringify({ upgraded: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.log('⚠️ Upgrade failed:', err.message);
    return new Response('Unauthorized', { status: 401 });
  }
});

router.post('/analytics/track', async (request, env, ctx) => {
  const { token, event } = await request.json();
  try {
    const user = await verifyJWT(token, ctx.env.JWT_SECRET);
    await env.DB.prepare('INSERT INTO analytics (user_id, event) VALUES (?, ?)')
      .bind(user.id, event)
      .run();

    return new Response(JSON.stringify({ tracked: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.log('⚠️ Tracking failed:', err.message);
    return new Response('Unauthorized', { status: 401 });
  }
});

router.post('/admin/overview', async (request, env, ctx) => {
  const { token } = await request.json();
  try {
    const user = await verifyJWT(token, ctx.env.JWT_SECRET);
    if (user.email !== 'admin@nexuschats.org') {
      return new Response('Forbidden', { status: 403 });
    }

    const stats = await env.DB.prepare('SELECT COUNT(*) AS total FROM users').first();
    return new Response(JSON.stringify({ stats }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.log('⚠️ Admin overview failed:', err.message);
    return new Response('Unauthorized', { status: 401 });
  }
});

router.post('/admin/send-email', async (request, env, ctx) => {
  const { token, subject, body } = await request.json();
  try {
    const user = await verifyJWT(token, ctx.env.JWT_SECRET);
    if (user.email !== 'admin@nexuschats.org') {
      return new Response('Forbidden', { status: 403 });
    }

    console.log(`📧 Sending email: ${subject}`);
    // Placeholder for email logic
    return new Response(JSON.stringify({ sent: true }), {
      headers: { 'Content-Type': 'application/json' },
    });
  } catch (err) {
    console.log('⚠️ Email send failed:', err.message);
    return new Response('Unauthorized', { status: 401 });
  }
});

export default {
  async fetch(request, env, ctx) {
    return router.handle(request, env, ctx);
  },
};
>>>>>>> cef45e7f81f3bd480eb5730685c8938173363872
