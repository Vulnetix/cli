import Router from "@koa/router";

const router = new Router();

router.patch("/me", async (ctx) => {
~>  ctx.state.user = { ...ctx.state.user, ...ctx.request.body };
  ctx.body = ctx.state.user;
});

export default router;
