import { exec as run } from 'child_process';

export async function lookup(request: any, reply: any) {
~>  run(`nslookup ${request.query.domain}`, (err, stdout) => {
    reply.send(stdout);
  });
}
