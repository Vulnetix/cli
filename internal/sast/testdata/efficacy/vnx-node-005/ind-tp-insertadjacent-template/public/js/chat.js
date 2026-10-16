export function appendMessage(container, message) {
~>  container.insertAdjacentHTML('beforeend', `<div class="msg">${message.text}</div>`);
}
