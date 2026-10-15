import { Response } from 'express';

export function issue(res: Response, accessToken: string): void {
~>  res.cookie("access_token", accessToken, {
    maxAge: 3600 * 1000,
    secure: true,
    sameSite: 'strict',
  });
}
