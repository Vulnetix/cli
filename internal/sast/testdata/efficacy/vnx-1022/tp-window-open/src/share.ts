export function openShare(target: string): void {
~>  window.open(target, '_blank');
}

export function openProfile(base: string, id: string): void {
~>  window.open(`${base}/u/${id}`);
~>  const w = window.open(partnerUrl + '/checkout', 'checkout', 'width=600');
  window.open('https://github.com/acme/app/wiki', '_blank');
}
