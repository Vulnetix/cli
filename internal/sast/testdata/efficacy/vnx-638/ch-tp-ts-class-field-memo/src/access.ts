import memoizeOne from "memoize-one";

export class AccessService {
~>  private readonly hasPermission = memoizeOne((user: User, perm: string) => this.api.check(user, perm));
~>  public canEdit = memoizeOne(async (userId: string) => this.api.canEdit(userId));
}
