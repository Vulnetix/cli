import Fastify from 'fastify'
import http from 'http'

const HOST = '0.0.0.0'
const PORT = Number(process.env.PORT ?? 8080)

const fastify = Fastify()
~>await fastify.listen({ port: PORT, host: '0.0.0.0' })

const metrics = http.createServer((req, res) => res.end('up'))
~>metrics.listen(9100, HOST)
