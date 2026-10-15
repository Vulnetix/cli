export function mountChat(siteId: string): void {
  const el: HTMLScriptElement = window.document.createElement("script");
  el.defer = true;
~>  el.src = `http://chat.example-support.com/widget/${siteId}.js`;
  document.body.appendChild(el);
}
