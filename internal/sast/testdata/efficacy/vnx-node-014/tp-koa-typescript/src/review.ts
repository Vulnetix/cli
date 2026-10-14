import type { Context } from 'koa';
import { Review } from './models/review';

export async function edit(ctx: Context): Promise<void> {
  const body = ctx.request.body as Record<string, unknown>;
~>  const updated = await Review.findOneAndUpdate({ _id: body.id }, { $set: { message: body.message } });
  ctx.body = updated;
}
