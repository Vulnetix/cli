import { UnsecuredJWT } from 'jose'

export function issue (sub: string): string {
~>  return new UnsecuredJWT({ sub }).setIssuedAt().setExpirationTime('1h').encode()
}

export function read (token: string) {
~>  return UnsecuredJWT.decode(token).payload
}
