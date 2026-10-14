export function rules(req, config) {
  const merged = wysihtml.lang.object({}).merge(config).get();
  const list = immutableMap.merge(req.body);
  return [merged, list];
}
