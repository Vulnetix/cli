export async function showPreview(container: HTMLElement, id: string): Promise<void> {
  const res = await fetch(`/api/preview/${id}`);
  const markup = await res.text();
~>  container.insertAdjacentHTML("beforeend", markup);
  const tpl = document.createElement("template");
~>  tpl.outerHTML = `<div class="preview">${markup}</div>`;
}
