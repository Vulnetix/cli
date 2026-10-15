~>const ORIGIN_RE = /^https:\/\/app\.example\.com(:\d+)?/;

export function allowOrigin(origin: string): boolean {
~>  return /^https:\/\/([\w-]+\.)?example\.io(:\d+)?/.test(origin);
}

export function allowRedirect(target: string): boolean {
~>  return new RegExp('^https://portal\\.example\\.org/?').test(target);
}
