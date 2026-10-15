async function call(accessToken) {
~>  console.debug('using token', accessToken);
~>  console.log("JWT secret:", @@sample:p[r]oc[e]ss[.]en[v][.]J[W]T[_][S]EC[R]ET@@);
  return fetch(url, { headers: { Authorization: `Bearer ${accessToken}` } });
}
