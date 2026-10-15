export function remember(cache: Map<string, string>, req: Request) {
  cache.set('last', req.query.q as string);
  settings.set('locale', req.body.locale);
  const headers = new Headers();
  return headers;
}
