import { Router } from 'itty-router';
import { SignJWT, jwtVerify } from 'jose';
import { sha256 } from 'hash-wasm';

const router = Router();

/* ---------------- JWT Helpers ---------------- */
async function signJWT(payload, secret) {
  return await new SignJWT(payload)
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime('7d')
    .sign(new TextEncoder().encode(secret));
}

async function verifyJWT(token, secret) {
  const { payload } = await jwtVerify(token, new TextEncoder().encode(secret));
  return payload;
}

/* ---------------- Routes ---------------- */

// /auth/login
router.post('/auth/login', async (request, env) => {
  try {
    const { email, password } = await request.json();
    console.log('📥 Login attempt for:', email);

    const user = await env.DB
      .prepare('SELECT * FROM users WHERE email = ?')
      .bind(email)
      .first();

    if (!user) {
      console.log('❌ No user found for:', email);
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const incomingHash = await sha256(password);
    if (incomingHash !== user.password_hash) {
      console.log('❌ Invalid password for:', email);
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const token = await signJWT(
      { id: user.id, email: user.email, plan: user.plan },
      env.JWT_SECRET
    );

    console.log('✅ JWT signed for:', email);
    return new Response(JSON.stringify({ token }), {
      status: 200,
      headers: { 'Content-Type': 'application/json' }
    });

  } catch (err) {
    console.error('💥 /auth/login error:', err);
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// /auth/me
router.post('/auth/me', async (request, env) => {
  try {
    const { token } = await request.json();
    const user = await verifyJWT(token, env.JWT_SECRET);
    return new Response(JSON.stringify({ user }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    console.log('⚠️ JWT verification failed:', err.message);
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// /auth/upgrade
router.post('/auth/upgrade', async (request, env) => {
  try {
    const { token } = await request.json();
    const user = await verifyJWT(token, env.JWT_SECRET);

    await env.DB
      .prepare('UPDATE users SET plan = ? WHERE id = ?')
      .bind('pro', user.id)
      .run();

    return new Response(JSON.stringify({ upgraded: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    console.log('⚠️ Upgrade failed:', err.message);
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// /analytics/track
router.post('/analytics/track', async (request, env) => {
  try {
    const { token, event } = await request.json();
    const user = await verifyJWT(token, env.JWT_SECRET);

    await env.DB
      .prepare('INSERT INTO analytics (user_id, event) VALUES (?, ?)')
      .bind(user.id, event)
      .run();

    return new Response(JSON.stringify({ tracked: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    console.log('⚠️ Tracking failed:', err.message);
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// /admin/overview
router.post('/admin/overview', async (request, env) => {
  try {
    const { token } = await request.json();
    const user = await verifyJWT(token, env.JWT_SECRET);

    if (user.email !== 'admin@nexuschats.org') {
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    const stats = await env.DB
      .prepare('SELECT COUNT(*) AS total FROM users')
      .first();

    return new Response(JSON.stringify({ stats }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    console.log('⚠️ Admin overview failed:', err.message);
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

// /admin/send-email
router.post('/admin/send-email', async (request, env) => {
  try {
    const { token, subject, body } = await request.json();
    const user = await verifyJWT(token, env.JWT_SECRET);

    if (user.email !== 'admin@nexuschats.org') {
      return new Response(JSON.stringify({ error: 'Forbidden' }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    console.log(`📧 Sending email: ${subject}`);
    // Placeholder for email logic
    return new Response(JSON.stringify({ sent: true }), {
      headers: { 'Content-Type': 'application/json' }
    });
  } catch (err) {
    console.log('⚠️ Email send failed:', err.message);
    return new Response(JSON.stringify({ error: 'Unauthorized' }), {
      status: 401,
      headers: { 'Content-Type': 'application/json' }
    });
  }
});

/* ---------------- Fallback ---------------- */
router.all('*', () =>
  new Response(JSON.stringify({ error: 'Not Found' }), {
    status: 404,
    headers: { 'Content-Type': 'application/json' }
  })
);

/* ---------------- Export ---------------- */
async function fetchHandler(request, env, ctx) {
  return router.handle(request, env, ctx);
}

export default { fetch: fetchHandler };ECHO is on.
// ?? GitHub sync trigger - 21:40 PKT 
