import { Pool } from 'pg';
~>import {
  UserService,
  DEFAULT_ROLE,
} from '../services/user';

export const pool = new Pool();

export function seed(): Promise<void> {
  return new UserService(pool).create('admin', DEFAULT_ROLE);
}
