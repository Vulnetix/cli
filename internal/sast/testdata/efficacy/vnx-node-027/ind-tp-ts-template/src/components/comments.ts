interface Comment { author: string; body: string }

export function render(list: HTMLElement, comments: Comment[]) {
  for (const c of comments) {
    const li = document.createElement('li');
~>    li.innerHTML = `<strong>${c.author}</strong>: ${c.body}`;
    list.appendChild(li);
  }
}
