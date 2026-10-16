export async function renderComments(list) {
  const res = await fetch('/api/comments');
  const comments = await res.json();
  for (const c of comments) {
    list.insertAdjacentHTML('beforeend', `<li class="c">${c.author}: ${c.body}</li>`);
  }
}
