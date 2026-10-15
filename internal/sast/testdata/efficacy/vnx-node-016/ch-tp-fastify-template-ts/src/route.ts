export async function grep(request: any, reply: any) {
~>  const matcher = RegExp(`${request.query.term}\\d+`, 'g');
  return reply.send(logLines.filter((l: string) => matcher.test(l)));
}
