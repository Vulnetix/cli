import { cookies } from 'next/headers';
import { redirect } from 'next/navigation';

export default async function AdminPage() {
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  const role = cookies().get('role')?.value;
  if (role !== 'admin') {
    redirect('/login');
  }
  return <h1>Admin</h1>;
}
