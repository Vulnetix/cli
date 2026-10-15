export interface CookieOptions {
  httpOnly?: boolean;
  sameSite: 'none' | 'lax' | 'strict';
  secure?: boolean;
}

export type SameSiteSetting = { sameSite: "none" | "lax" };

export const defaults: CookieOptions = { sameSite: 'lax', httpOnly: true };
