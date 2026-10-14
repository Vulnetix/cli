export function Card({ html }: { html: string }) {
  return (
    <section
~>      dangerouslySetInnerHTML={{
        __html: html,
      }}
    />
  );
}

export function mount(root: HTMLElement, title: string) {
~>  root.innerHTML = `
    <header>
      <h1>${title}</h1>
    </header>`;
}
