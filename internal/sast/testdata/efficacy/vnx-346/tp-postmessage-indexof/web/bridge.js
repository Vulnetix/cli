window.addEventListener("message", (event) => {
~>  if (event.origin.includes("trusted-partner.com")) {
    document.getElementById("out").innerHTML = event.data.html;
  }
});

function onMsg(e) {
~>  if (!e.origin.endsWith("example.org")) return;
  runCommand(e.data);
}
