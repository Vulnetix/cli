export async function openTickets(clientId: string) {
  const res = await fetch(`/api/tickets?client_id=${clientId}&state=open`);
  return res.json();
}

export async function closedTickets(clientId: string) {
  return fetch("/api/tickets?state=closed&client_id=" + clientId);
}
