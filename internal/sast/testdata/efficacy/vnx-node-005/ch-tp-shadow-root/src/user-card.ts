class UserCard extends HTMLElement {
  connectedCallback() {
    const name = this.getAttribute("name");
~>    this.shadowRoot!.innerHTML = `
      <style>:host { display: block }</style>
      <span class="name">${name}</span>
    `;
  }
}
customElements.define("user-card", UserCard);
