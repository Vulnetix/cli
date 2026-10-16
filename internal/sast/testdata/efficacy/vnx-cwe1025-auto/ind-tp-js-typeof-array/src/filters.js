export function normalise(filter) {
  if (filter == null) return [];
~>  if (typeof filter === 'array') {
    return filter;
  }
  return [filter];
}
