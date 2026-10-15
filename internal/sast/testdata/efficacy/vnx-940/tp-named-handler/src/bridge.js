function receive(evt) {
  const payload = JSON.parse(evt.data);
  localStorage.setItem('token', payload.token);
  document.title = payload.title;
}

~>window.addEventListener("message", receive, false);

const onResize = (e) => {
  document.body.style.height = e.data.height + 'px';
};
~>addEventListener('message', onResize);
