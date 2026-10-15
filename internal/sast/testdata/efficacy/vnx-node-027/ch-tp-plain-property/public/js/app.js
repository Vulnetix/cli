fetch('/api/messages')
  .then((r) => r.json())
  .then((data) => {
    const box = document.getElementById('messages');
~>    box.innerHTML = data.message;
  });
