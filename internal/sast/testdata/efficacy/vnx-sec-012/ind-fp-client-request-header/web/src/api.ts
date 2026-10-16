// The browser sends Origin itself; this only documents the header name.
export async function load(url: string) {
  const res = await fetch(url, {
    headers: { 'Access-Control-Allow-Origin': '*', Accept: 'application/json' },
  });
  return res.json();
}
