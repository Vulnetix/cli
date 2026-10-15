import { sessionCookieOptions, baseCookie } from './cookie-config';

export function login(res: any, sid: string, token: string) {
  res.cookie('session', sid, sessionCookieOptions());
  res.cookie('token', token, { ...baseCookie, maxAge: 900000 });
}
