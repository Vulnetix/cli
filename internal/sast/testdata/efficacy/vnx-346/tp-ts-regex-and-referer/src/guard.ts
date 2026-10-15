export function trusted(req: Request): boolean {
  const origin = req.headers.get("origin") ?? "";
~>  return /example\.com/.test(origin);
}

export function fromSite(): boolean {
~>  return document.referrer.indexOf("https://example.com") === 0;
}
