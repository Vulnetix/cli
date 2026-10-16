router.post('/pay', async (ctx) => {
  const { cvv } = ctx.request.body as { cvv: string };
~>  ctx.cookies.set('card_cvv', cvv, { httpOnly: true, maxAge: 600000 });
  ctx.redirect('/pay/confirm');
});
