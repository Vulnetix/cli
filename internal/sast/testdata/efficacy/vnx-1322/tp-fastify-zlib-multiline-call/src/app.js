import Fastify from 'fastify'
import zlib from 'node:zlib'

const fastify = Fastify()

fastify.post('/compress', async function (request, reply) {
  const level = Number(request.query.level || 6)
~>  const packed = zlib.gzipSync(
    Buffer.from(JSON.stringify(request.body)),
    { level }
  )
  reply.header('content-encoding', 'gzip').send(packed)
})

export default fastify
