export function title(el, user) {
  el.innerHTML = `<h2>${user.name}</h2>`;
  el["innerHTML"] = user.bio;
  // host.insertAdjacentHTML('beforeend', `<p>${user.bio}</p>`);
}
