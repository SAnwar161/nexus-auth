// Add this route to handle analytics tracking
router.post('/analytics/track', async (ctx) => {
  const authHeader = ctx.req.header('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return new Response('Unauthorized', { status: 401 });
  }

  const token = authHeader.split(' ')[1];
  const user = await verifyJWT(token); // Use your existing JWT verification logic
  if (!user) return new Response('Invalid token', { status: 403 });

  const { event, metadata } = await ctx.req.json();
  const timestamp = new Date().toISOString();

  await ctx.env.DB.prepare(`
    INSERT INTO analytics (user_id, event, metadata, timestamp)
    VALUES (?, ?, ?, ?)
  `).bind(user.id, event, JSON.stringify(metadata || {}), timestamp).run();

  return new Response('Event tracked', { status: 200 });
});
