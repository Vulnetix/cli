import { http } from "./http";

export async function fetch_user(id: string): Promise<User> {
  return http.get<User>(`/users/${id}`);
}

~>export async function fetchUser(id: string, opts: { cache?: boolean } = {}): Promise<User> {
  const res = await http.get<User>(`/v2/users/${id}`, opts);
  return res;
}
