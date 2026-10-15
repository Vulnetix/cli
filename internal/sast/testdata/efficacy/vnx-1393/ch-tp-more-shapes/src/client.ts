import { Client } from 'pg';

export const db = new Client({
  host: 'pg',
~>  password: process.env.PGPASSWORD ?? 'postgres',
});
