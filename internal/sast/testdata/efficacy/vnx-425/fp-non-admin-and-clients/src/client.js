import axios from 'axios'

export async function loadUsers() {
  const res = await axios.get('/api/admin/users')
  const other = await http.get('/admin/stats')
  return [res.data, other]
}

const settings = new Map()
settings.get('admin/users')
app.get('/administer-docs-like-path', docs.show)
app.get('/admins-guide', docs.guide)
