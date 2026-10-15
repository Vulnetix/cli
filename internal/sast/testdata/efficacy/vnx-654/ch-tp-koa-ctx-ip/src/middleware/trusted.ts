import type { Context, Next } from 'koa';

const TRUSTED = ['127.0.0.1', '::1'];

export async function trusted(ctx: Context, next: Next) {
~>  if (TRUSTED.includes(ctx.ip)) {
    await next();
    return;
  }
  ctx.status = 403;
}

export async function trustedProxy(ctx: Context, next: Next) {
~>  if (ctx.request.ip.startsWith('10.')) {
    return await next();
  }
  ctx.throw(403);
}
