import jsonwebtoken from 'jsonwebtoken';

export function whoAmI(token: string) {
~>  const payload = jsonwebtoken.decode(token, { complete: true });
  return payload?.payload;
}
