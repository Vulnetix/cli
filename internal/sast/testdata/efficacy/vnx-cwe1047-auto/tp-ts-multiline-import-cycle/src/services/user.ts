import { pool } from '../db';

export const DEFAULT_ROLE = 'viewer';

export class UserService {
  constructor(private readonly db = pool) {}

  async create(name: string, role: string): Promise<void> {
    await this.db.query('INSERT INTO users(name, role) VALUES ($1, $2)', [name, role]);
  }
}
