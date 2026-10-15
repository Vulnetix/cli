server.route({
  method: "GET",
  path: "/out",
~>  handler: (request, h) => h.redirect(request.query.url),
});

export function afterLogin() {
  const params = new URLSearchParams(window.location.search);
  const next = params.get("redirect");
~>  window.location.assign(next);
}
