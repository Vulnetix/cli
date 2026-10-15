function isStaff(user) {
  return user.email.endsWith('@acme.com');
}

function isDocsAsset(file) {
  return file.name.includes('docs.acme.com');
}

function trustedEmail(email) {
  return email.endsWith('acme.com');
}

module.exports = { isStaff, isDocsAsset, trustedEmail };
