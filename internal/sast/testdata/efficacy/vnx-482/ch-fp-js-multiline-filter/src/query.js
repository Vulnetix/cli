const active = users.filter(
  (u) =>
    u.status === "active"
);

const isAdmin =
  role === "admin";

export default function check(a, b) {
  return (
    a == b
  );
}
