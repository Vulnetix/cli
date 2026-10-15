export async function load() {
  const res = await fetch('/api/orders', {
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
    },
  });
  return res.json();
}

export const get = (url) => axios.get(url, { headers: { 'Access-Control-Allow-Origin': '*' } });
