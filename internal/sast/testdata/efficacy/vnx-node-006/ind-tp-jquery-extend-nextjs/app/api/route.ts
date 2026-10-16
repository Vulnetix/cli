import merge from "lodash/merge";

export async function PATCH(request: Request) {
  const current = { theme: "light", locale: "en" };
  const patch = await request.json();
~>  const next = merge(current, patch);
  return Response.json(next);
}
