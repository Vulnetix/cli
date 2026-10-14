function addRow(list, entry) {
  const li = document.createElement('li');
~>  li.innerHTML += entry.message;
  list.appendChild(li);
}

function replaceBanner(banner, text) {
~>  banner.outerHTML = '<div class="banner">' + text + '</div>';
}
