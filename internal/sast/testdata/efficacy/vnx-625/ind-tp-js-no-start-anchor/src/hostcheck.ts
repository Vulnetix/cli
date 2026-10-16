export function trusted(origin: string): boolean {
~>  return /trusted-partner\.io$/.test(origin)
}
