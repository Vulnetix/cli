export function renderUser(el, user) {
  el.textContent = user.name;
  el.innerText = user.bio;
  const li = document.createElement('li');
  li.append(document.createTextNode(user.comment));
  el.setAttribute('title', user.name);
}
