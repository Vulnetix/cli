import { merge as deepMerge } from "lodash-es";

export async function patchSettings(ctx) {
  const current = await ctx.state.settings.load();
~>  const next = deepMerge(current, ctx.request.body);
  ctx.body = await ctx.state.settings.save(next);
}
