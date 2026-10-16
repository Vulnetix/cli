export function renderUser(el: HTMLElement, user: { name: string; bio: string }) {
  el.innerHTML = `<h2>${user.name}</h2><p>${user.bio}</p>`;
}

export function appendComment(list: HTMLElement, text: string) {
  list.innerHTML += "<li>" + text + "</li>";
}
