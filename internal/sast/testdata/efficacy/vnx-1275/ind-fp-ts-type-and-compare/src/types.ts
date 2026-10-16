export type SameSiteValue = 'lax' | 'strict' | 'none';

export interface CookieOpts {
  sameSite?: 'lax' | 'strict' | 'none' | boolean;
}

export function isEmbed(o: CookieOpts): boolean {
  return o.sameSite === 'none';
}
