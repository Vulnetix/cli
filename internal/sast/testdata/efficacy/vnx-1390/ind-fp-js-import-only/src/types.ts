import { DigestStrategy } from 'passport-http';
export type S = typeof DigestStrategy;
export const bearer = (t: string) => ({ Authorization: `Bearer ${t}` });
