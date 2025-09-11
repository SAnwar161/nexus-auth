import { Router } from 'itty-router';
import { verifyJWT } from './lib/jwt'; // Adjust path if needed

const router = Router();

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

// Add other routes below...

export default {
  async fetch(request, env, ctx) {
    return router.handle(request, env, ctx);
  }
};
