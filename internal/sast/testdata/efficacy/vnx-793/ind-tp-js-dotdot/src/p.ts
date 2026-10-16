export function clean(relativePath: string): string {
~>  relativePath = relativePath.replace('..', '.')
  return relativePath;
}
