import { Response } from 'express';

export function setAuth(res: Response, jwt: string) {
~>  res.cookie('auth_token', jwt, { httpOnly: false, secure: true, sameSite: 'strict', maxAge: 3600000 });
}
