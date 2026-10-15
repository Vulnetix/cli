export class AdminGuard {
  canActivate(context: ExecutionContext): boolean {
    try {
      return this.roles.check(context);
~>    } catch { return true; }
  }
}

export const checkPermission = async (user: User, perm: string): Promise<boolean> => {
  try {
    return await acl.has(user, perm);
  } catch (error) {
    console.error(error);
~>    return true;
  }
};
