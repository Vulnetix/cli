import axios from 'axios';
import { Agent } from 'https';
import type { ConnectionOptions } from 'tls';

export const api = axios.create({
  baseURL: process.env.API_URL,
~>  httpsAgent: new Agent({ rejectUnauthorized: false }),
});

export function tlsOptions(host: string): ConnectionOptions {
  const opts: ConnectionOptions = { host, port: 443 };
~>  opts.rejectUnauthorized = false;
  return opts;
}
