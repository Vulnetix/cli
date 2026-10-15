const DEFAULTS = { page: 1, perPage: 20 };

export function listOptions(req: { query: Record<string, string> }) {
  const options = { ...DEFAULTS, ...req.query };
  const merged = Object.assign({}, DEFAULTS, req.query);
  return { options, merged };
}
