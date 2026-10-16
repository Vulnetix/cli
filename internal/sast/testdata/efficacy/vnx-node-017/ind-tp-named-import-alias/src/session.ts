import { unserialize as restore, serialize } from 'node-serialize';
import type { Request } from 'express';

export function load(req: Request) {
  const raw = req.body.state;
~>  return restore(raw);
}

export function save(state: object) {
  return serialize(state);
}
