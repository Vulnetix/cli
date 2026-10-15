export function looksLikeEmail(value: string): boolean {
~>  if (value.search(/@/)) {
    return true;
  }
  return false;
}
