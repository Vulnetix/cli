const params = new URLSearchParams(window.location.search);
const message = params.get("msg");
const banner = document.getElementById("banner");
banner.innerHTML = message;
