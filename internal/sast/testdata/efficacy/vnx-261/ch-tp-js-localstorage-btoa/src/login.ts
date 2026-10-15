export function rememberUser(form: HTMLFormElement) {
  const user = (form.elements.namedItem("user") as HTMLInputElement).value;
  const pwd = (form.elements.namedItem("password") as HTMLInputElement).value;
  localStorage.setItem("user", user);
~>  localStorage.setItem("pw", window.btoa(pwd));
}

export function saveServerSide(req: any, store: any) {
~>  const stored = Buffer.from(
    req.body.password,
    "utf8",
  ).toString("base64");
  store.put(req.body.email, stored);
}
