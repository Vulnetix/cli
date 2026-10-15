// The server must answer with Access-Control-Allow-Origin: * for this to work.
export async function load() {
  const r = await fetch('https://api.example.com/data', { mode: 'cors' });
  const acao = r.headers.get('Access-Control-Allow-Origin');
  return { acao, body: await r.json() };
}
