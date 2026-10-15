import { useState } from 'react';

export function Search() {
  const [query, setQuery] = useState('');
  async function run() {
    const res = await fetch('/api/search?q=' + encodeURIComponent(query));
    return res.json();
  }
  // a server would never do fetch(req.query.url) like this
  const note = "avoid axios.get(req.body.url) on the server";
  return <input value={query} onChange={(e) => setQuery(e.target.value)} onBlur={run} title={note} />;
}
