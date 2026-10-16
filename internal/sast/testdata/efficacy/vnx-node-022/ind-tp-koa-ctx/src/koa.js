import shelljs from 'shelljs';
export async function lookup(ctx) {
~>  shelljs.exec(`whois ${ctx.query.domain}`);
  ctx.body = 'ok';
}
