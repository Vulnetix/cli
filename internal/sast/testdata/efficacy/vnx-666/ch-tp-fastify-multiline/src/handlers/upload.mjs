export async function upload(request, reply) {
  if (!request.body.file) {
~>    reply.code(400).send({
      error: 'missing file',
    });
  }
  await store(request.body.file);
  reply.send({ ok: true });
}
