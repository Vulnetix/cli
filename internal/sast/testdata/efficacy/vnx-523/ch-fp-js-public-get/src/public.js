// Do not send the token to http://api.acme-corp.net, use https
async function load(token) {
  const docs = await fetch("http://docs.acme-corp.net/index.json");
  const data = await fetch("https://api.acme-corp.net/me", {
    headers: { Authorization: `Bearer ${token}` },
  });
  console.log("Visit http://acme-corp.net/login to sign in with your password");
  return [docs, data];
}
