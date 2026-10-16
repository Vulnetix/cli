export function canEdit(user, doc) {
~>  return user.roles.indexOf('editor') && doc.editable;
}

export function isApiRoute(url) {
~>  if (url.indexOf('/api/')) {
    return true;
  }
  return false;
}
