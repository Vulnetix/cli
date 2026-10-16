export const ACCESS_CONTROL_ALLOW_ORIGIN = 'Access-Control-Allow-Origin';
export const CORS_HELP = "Set Access-Control-Allow-Origin: * only for public assets";

export function describe(h: Headers): string {
  return h.get('Access-Control-Allow-Origin') ?? 'none';
}
