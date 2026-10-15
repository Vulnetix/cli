export function issue(res: Response, token: string) {
~>  res.cookie('authToken', token, {
    httpOnly: true,
    expires: new Date(Date.now() + 90 * 24 * 60 * 60 * 1000),
  });
}
