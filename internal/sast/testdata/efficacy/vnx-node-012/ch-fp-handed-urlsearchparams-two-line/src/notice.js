const params = new URLSearchParams(window.location.search);
const msg = params.get('msg');
document.getElementById('notice').innerHTML = msg;
