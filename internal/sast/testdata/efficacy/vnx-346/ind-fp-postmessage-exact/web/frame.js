const TRUSTED = "https://widgets.acme.io";

window.addEventListener("message", (event) => {
  // Previously: if (event.origin.indexOf("acme.io") > -1)
  if (event.origin !== TRUSTED) return;
  const msg = "origin.includes('acme.io') is unsafe";
  render(event.data, msg);
});
