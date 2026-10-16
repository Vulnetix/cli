function renderTodos(list, todos) {
  for (const item of todos) {
    list.innerHTML += `<li class="todo">${item.title}</li>`;
  }
~>  document.writeln("<p>Total: " + todos.length + " for " + todos.owner + "</p>");
}
