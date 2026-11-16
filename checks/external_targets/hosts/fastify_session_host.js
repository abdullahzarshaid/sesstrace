'use strict'
// Minimal host application around @fastify/session at a pinned commit.
// It speaks the endpoint contract of the SessTrace "profile" operation: /login, /profile, /logout.
// Usage: node fastify_session_host.js <path of the checked-out library> <port> <lifetime in seconds>
const lib = process.argv[2]
const port = parseInt(process.argv[3], 10)
const lifetimeMs = parseInt(process.argv[4], 10) * 1000
const fastify = require(require.resolve('fastify', { paths: [lib] }))({ logger: false })

fastify.register(require(require.resolve('@fastify/cookie', { paths: [lib] })))
fastify.register(require(lib), {
  secret: 'sesstrace-external-target-test-secret-0001',
  cookieName: 'sid',
  saveUninitialized: false,
  cookie: { secure: false, httpOnly: true, path: '/', maxAge: lifetimeMs }
})

fastify.get('/login', async (request, reply) => {
  const user = String(request.query.user || '')
  if (user !== 'alice' && user !== 'bob') { reply.code(400); return { error: 'invalid_request' } }
  request.session.user = user
  return { logged_in: true }
})

fastify.get('/profile', async (request, reply) => {
  const user = request.session && request.session.user
  if (!user) { reply.code(401); return { error: 'no_session' } }
  return { sub: user, rp: 'RP1' }
})

fastify.get('/logout', async (request, reply) => {
  await new Promise((resolve, reject) => request.session.destroy(err => (err ? reject(err) : resolve())))
  return { logged_out: true }
})

fastify.get('/ready', async () => ({ ok: true }))

fastify.listen({ port, host: '127.0.0.1' })
  .then(() => console.log('READY'))
  .catch(err => { console.error(err); process.exit(1) })
