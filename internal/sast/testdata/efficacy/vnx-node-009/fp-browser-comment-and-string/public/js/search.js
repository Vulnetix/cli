// Browser code: fetch(req.query.url) is a server-side concern, not here.
const form = document.querySelector('#search');

form.addEventListener('submit', async (event) => {
  event.preventDefault();
  const term = document.querySelector('#q').value;
  const r = await fetch('/api/search?q=' + encodeURIComponent(term));
  render(await r.json());
});

const docs = 'Never write fetch(req.query.url) on the server';
/* axios.get(req.body.url) */
