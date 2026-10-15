import Router from '@koa/router';
import { authenticate } from './auth';

const router = new Router({ prefix: '/api' });

~>router.post(['/signin', '/sign-in'], async (ctx) => {
  const { email, password } = ctx.request.body as any;
  ctx.body = await authenticate(email, password);
});

~>router.post('verifyOtp', '/verify-otp', async (ctx) => {
  ctx.body = { ok: true };
});

router.get('/me', async (ctx) => {
  ctx.body = ctx.state.user;
});

export default router;
