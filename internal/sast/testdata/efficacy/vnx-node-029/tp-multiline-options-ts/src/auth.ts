import { Response } from 'express';

export function setAuthCookie(res: Response, accessToken: string): void {
~>  res.cookie('access_token', accessToken, {
    secure: true,
    sameSite: 'strict',
    maxAge: 15 * 60 * 1000,
  });
}
