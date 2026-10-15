function isObject(v: unknown): v is Record<string, unknown> {
  return typeof v === "object" && v !== null && !Array.isArray(v);
}

export function deepMerge(dst: any, src: any): any {
  Object.entries(src).forEach(([k, v]) => {
    if (isObject(v)) {
      dst[k] = dst[k] || {};
~>      deepMerge(dst[k], v);
    } else {
      dst[k] = v;
    }
  });
  return dst;
}
