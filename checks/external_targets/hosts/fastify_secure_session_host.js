'use strict'
// Minimal host application around @fastify/secure-session at a pinned commit.
// It speaks the endpoint contract of the SessTrace "profile" operation: /login, /profile, /logout.
// Usage: node fastify_secure_session_host.js <path of the checked-out library> <port> <lifetime in seconds>
// The option "expiry" exists only after the repair; the earlier revision ignores it.
const lib = process.argv[2]
const port = parseInt(process.argv[3], 10)
const lifetimeSeconds = parseInt(process.argv[4], 10)
const fastify = require(require.resolve('fastify', { paths: [lib] }))({ logger: false })

fastify.register(require(lib), {
  // fixed test key, 32 bytes; it protects nothing outside this throw-away process
  key: Buffer.from('5e55747261636520657874206b6579205e55747261636520657874206b657921', 'hex'),
  cookieName: 'sid',
  expiry: lifetimeSeconds,
  cookie: { path: '/', httpOnly: true }
})

fastify.get('/login', async (request, reply) => {
  const user = String(request.query.user || '')
  if (user !== 'alice' && user !== 'bob') { reply.code(400); return { error: 'invalid_request' } }
  request.session.set('user', user)
  return { logged_in: true }
})

fastify.get('/profile', async (request, reply) => {
  const user = request.session && request.session.get('user')
  if (!user) { reply.code(401); return { error: 'no_session' } }
  return { sub: user, rp: 'RP1' }
})

fastify.get('/logout', async (request, reply) => {
  request.session.delete()
  return { logged_out: true }
})

fastify.get('/ready', async () => ({ ok: true }))

fastify.listen({ port, host: '127.0.0.1' })
  .then(() => console.log('READY'))
  .catch(err => { console.error(err); process.exit(1) })
