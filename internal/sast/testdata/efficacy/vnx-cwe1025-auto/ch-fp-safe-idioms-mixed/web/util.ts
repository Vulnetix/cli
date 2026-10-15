export function isEmpty(obj: Record<string, unknown> | null, items: string[]): boolean {
  if (obj === null || typeof obj !== 'object') {
    return true;
  }
  if (Array.isArray(items) && items.length === 0) {
    return true;
  }
  if (JSON.stringify(obj) === '{}') {
    return true;
  }
  const opts = obj === undefined ? {} : obj;
  return Object.keys(opts).length === 0;
}

export function withDefaults(config = {}, list = []) {
  const kind = typeof config;
  if (kind === 'function') {
    return list;
  }
  return config;
}
