function renderComment(comment) {
  const box = document.querySelector('#comments');
~>  box.innerHTML = `<p class="c">${comment.body}</p>`;
}

window.addEventListener('message', (event) => {
  const html = event.data;
~>  document.body.innerHTML=html;
});
