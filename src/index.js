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

/* ---------------- CORS Headers ---------------- */
function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": "https://nexuschats.org",
    "Access-Control-Allow-Methods": "POST, GET, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Content-Type": "application/json"
  };
}

/* ---------------- Routes ---------------- */
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
        headers: corsHeaders()
      });
    }

    const incomingHash = await sha256(password);
    if (incomingHash !== user.password_hash) {
      console.log('❌ Invalid password for:', email);
      return new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: corsHeaders()
      });
    }

    const token = await signJWT(
      { id: user.id, email: user.email, plan: user.plan },
      env.JWT_SECRET
    );

    console.log('✅ JWT signed for:', email);
    return new Response(JSON.stringify({ token }), {
      status: 200,
      headers: corsHeaders()
    });

  } catch (err) {
    console.error('💥 /auth/login error:', err);
    return new Response(JSON.stringify({ error: 'Internal Server Error' }), {
      status: 500,
      headers: corsHeaders()
    });
  }
});

/* ---------------- Fallback ---------------- */
router.all('*', () =>
  new Response(JSON.stringify({ error: 'Not Found' }), {
    status: 404,
    headers: corsHeaders()
  })
);

/* ---------------- Export ---------------- */
async function fetchHandler(request, env, ctx) {
  if (request.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders()
    });
  }

  return router.handle(request, env, ctx);
}

export default { fetch: fetchHandler };
