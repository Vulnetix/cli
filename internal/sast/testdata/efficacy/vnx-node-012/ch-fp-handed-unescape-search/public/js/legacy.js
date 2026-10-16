var box = document.getElementById('welcome');
box.innerHTML = 'Welcome, ' + unescape(location.search.substring(6));
