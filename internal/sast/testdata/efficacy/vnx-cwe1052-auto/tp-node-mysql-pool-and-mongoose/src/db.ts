import mysql from 'mysql2/promise';
import mongoose from 'mongoose';
import { createClient } from 'redis';

export const pool = mysql.createPool({
~>  host: 'db-primary.acme.net',
  user: 'shop',
  database: 'shop',
  connectionLimit: 10,
});

export async function connectDocs(): Promise<void> {
~>  await mongoose.connect(`mongodb://10.1.1.5:27017/shop`);
}

~>export const redis = createClient({ url: "redis://cache.acme.net:6379/0" });
