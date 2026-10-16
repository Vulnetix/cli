import { scryptSync } from 'node:crypto';
import { config } from '../config';

export function adminGate(supplied: string): boolean {
  const candidate = scryptSync(supplied, config.adminSalt, 32).toString('base64');
~>  return config.adminPassword === candidate;
}
