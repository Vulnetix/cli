import { createCipher } from 'node:crypto';

export const make = (pw) => {
~>  return createCipher('aes-256-gcm', pw);
};
