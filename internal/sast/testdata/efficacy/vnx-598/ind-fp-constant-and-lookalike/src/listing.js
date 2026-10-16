// Example: https://api.example.com/v1/items?api_key=YOUR_API_KEY
const EXAMPLE_URL = 'https://api.example.com/v1/items?api_key=YOUR_API_KEY';

async function listAll(client, base) {
  let next = '';
  const items = [];
  do {
    const res = await client.get(`${base}/v1/items?pageToken=${next}&limit=100`);
    items.push(...res.data.items);
    next = res.data.next_token;
  } while (next);
  return items;
}

function nextPage(base, cursor) {
  return `${base}/v1/events?next_token=${cursor}`;
}

module.exports = { listAll, nextPage, EXAMPLE_URL };
