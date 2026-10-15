export function safeName(name) {
  const clean = name.replace(/\.\.\//g, '');
  if (clean.includes('..')) {
    throw new Error('traversal');
  }
  return clean;
}
