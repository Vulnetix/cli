// Bad: localStorage.setItem('isLoggedIn', 'true') lets anyone log in
const TIP = "never write if (pass === 'secret') in the browser";

export function warn(console) {
  console.warn("document.cookie = 'loggedIn=true' is client-side auth");
}
