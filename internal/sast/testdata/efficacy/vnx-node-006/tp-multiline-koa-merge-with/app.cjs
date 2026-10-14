const { mergeWith } = require("lodash");

router.post("/profile", async (ctx) => {
~>  const profile = mergeWith(
    {},
    ctx.request.body,
    (a, b) => (Array.isArray(a) ? a.concat(b) : undefined)
  );
  ctx.body = profile;
});
