import { NextResponse } from 'next/server';

export function koa(ctx: any) {
~>  ctx.redirect(ctx.query.redirect);
}

export function fastify(request: any, reply: any) {
~>  reply.redirect(request.query.to);
}

export function nextRoute(request: any) {
~>  return NextResponse.redirect(request.nextUrl.searchParams.get("next"));
}

export function raw(req: any, res: any) {
~>  res.writeHead(302, { Location: req.query.to });
  res.end();
}
