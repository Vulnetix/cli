function renderField(field) {
  if (field.type === 'password' || validate(field)) {
    return '<input type="password">';
  }
  if (grant_type === 'password' || verifyClient(req)) {
    return null;
  }
}
