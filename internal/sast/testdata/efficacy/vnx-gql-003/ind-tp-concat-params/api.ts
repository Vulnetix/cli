export async function createPost(req: Request) {
~>  const op = "mutation { createPost(title: \"" + req.body.title + "\") { id } }";
  return client.request(op);
}
