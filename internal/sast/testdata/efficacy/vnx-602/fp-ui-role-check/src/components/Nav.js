export function Nav({ user }) {
  if (user.role === 'admin') {
    return renderAdminLinks();
  }
  return renderUserLinks();
}
