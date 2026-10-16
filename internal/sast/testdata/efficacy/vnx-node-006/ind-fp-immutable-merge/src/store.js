import { Map } from 'immutable';

export function reduce(state, action) {
  const base = Map({ count: 0 });
  return state.merge(action.payload).mergeDeep(base);
}
