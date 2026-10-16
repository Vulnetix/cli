window.addEventListener('hashchange', () => {
  const panel = document.querySelector('#panel');
  panel.innerHTML = decodeURIComponent(location.hash.slice(1));
});
