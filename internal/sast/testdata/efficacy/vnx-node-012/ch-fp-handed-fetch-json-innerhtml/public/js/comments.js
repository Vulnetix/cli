async function loadComments(postId) {
  const resp = await fetch(`/api/posts/${postId}/comments`);
  const comments = await resp.json();
  const list = document.querySelector('#comments');
  for (const c of comments) {
    list.innerHTML += `<li><b>${c.author}</b>: ${c.text}</li>`;
  }
}
