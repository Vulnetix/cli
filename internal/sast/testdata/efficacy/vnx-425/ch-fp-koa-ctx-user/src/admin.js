const Router = require("@koa/router");

const router = new Router();

router.post("/admin/flags/:name", async (ctx) => {
  if (!ctx.state.user || !ctx.state.user.admin) {
    ctx.throw(403, "admins only");
  }
  await flags.toggle(ctx.params.name);
  ctx.status = 204;
});

module.exports = router;
