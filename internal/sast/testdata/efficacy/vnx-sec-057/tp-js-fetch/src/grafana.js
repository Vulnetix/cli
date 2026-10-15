export async function annotate(text) {
  return fetch("https://grafana.acme.internal/api/annotations", {
    method: "POST",
~>    headers: { Authorization: `Bearer glsa_@@sample:[A-Za-z0-9]{32}@@_@@sample:[a-f0-9]{8}@@` },
    body: JSON.stringify({ text }),
  });
}
