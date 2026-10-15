import * as ns from 'node-serialize';

export function restoreSession(req) {
  const state = req.body.state;
~>  return ns.unserialize(
    state
  );
}
