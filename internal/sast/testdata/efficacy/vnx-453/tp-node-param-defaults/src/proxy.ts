export async function forward(
  target: string,
~>  rejectUnauthorized: boolean = false,
): Promise<Response> {
  return fetch(target);
}
