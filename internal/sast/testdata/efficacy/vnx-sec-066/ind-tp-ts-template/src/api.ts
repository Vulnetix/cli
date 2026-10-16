export async function listRepos() {
  return fetch('https://api.acme-corp.io/repos', {
    headers: {
~>      'Authorization': `Bearer @@sample:[A-Za-z0-9]{32}@@`,
    },
  });
}
