export function renderCard(el, user) {
~>  el.innerHTML = `
    <div class="card">
      <h2>${user.name}</h2>
      <p>${user.bio}</p>
    </div>
  `;
}
