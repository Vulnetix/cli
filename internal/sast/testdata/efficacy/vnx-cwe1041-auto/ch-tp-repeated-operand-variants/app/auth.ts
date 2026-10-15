export function canPublish(req: Request & { user?: User }): boolean {
~>  if (req.user && req.user.isEditor && req.user.isEditor) {
    return true;
  }
  return false;
}
