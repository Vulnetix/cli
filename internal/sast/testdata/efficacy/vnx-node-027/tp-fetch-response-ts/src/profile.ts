export async function showProfile(id: string): Promise<void> {
  const res = await fetch(`/api/users/${id}`);
  const user = await res.json();
  const card = document.getElementById('card') as HTMLElement;
~>  card.innerHTML =
    '<h2>' + user.displayName + '</h2>';
}
