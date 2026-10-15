export function wire(link: HTMLAnchorElement, out: HTMLElement, q: string): void {
  link.href = '/search?q=' + encodeURIComponent(q);
  out.textContent = decodeURIComponent(location.hash.slice(1));
  out.innerHTML = '';
  const img = document.createElement('img');
  img.src = `/avatars/${encodeURIComponent(q)}.png`;
  out.appendChild(img);
}
