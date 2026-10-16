export class UserStore {
  get_user(id: string): User | undefined {
    return this.users.get(id);
  }

  list(): User[] {
    return [...this.users.values()];
  }

~>  getUser(id: string): User | undefined {
    return this.cache.get(id);
  }
}
