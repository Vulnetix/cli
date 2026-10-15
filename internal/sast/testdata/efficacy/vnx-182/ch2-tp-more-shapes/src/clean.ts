export function cleanName(name: string): string {
~>  return name.replace(/\.\.\//g, '');
}
