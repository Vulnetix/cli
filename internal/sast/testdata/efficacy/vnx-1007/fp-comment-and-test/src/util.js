// Reject usernames such as "аdmin" that use a Cyrillic а.
export function normalise(name) {
  return name.normalize('NFKC');
}
