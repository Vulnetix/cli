interface Todo { title: string; owner: string }

export function renderTodos(list: HTMLElement, todos: Todo[]): void {
  for (const todo of todos) {
    list.innerHTML += `<li>${todo.title} <small>${todo.owner}</small></li>`;
  }
}

export function appendRow(table: HTMLTableElement, user: { name: string }): void {
  const row = '<tr><td>' + user.name + '</td></tr>';
  table.insertAdjacentHTML('beforeend', row);
}
