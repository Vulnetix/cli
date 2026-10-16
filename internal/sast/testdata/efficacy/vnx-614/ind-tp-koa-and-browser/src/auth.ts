import Koa from 'koa';
import Router from '@koa/router';
import { issueToken } from './tokens';

const router = new Router();

router.post('/session', async (ctx: Koa.Context) => {
  const jwt = await issueToken(ctx.request.body);
~>  ctx.cookies.set('jwt', jwt, { httpOnly: true, sameSite: 'lax' });
  ctx.body = { ok: true };
});

export function rememberInBrowser(token: string): void {
~>  document.cookie = "access_token=" + token + "; path=/; SameSite=Lax";
}

export function rememberSession(sessionId: string): void {
~>  document.cookie = `session_id=${sessionId}; path=/`;
}

export default router;
