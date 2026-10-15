export function issueToken (user: string): string {
~>  const secret = 'dev-secret' // TODO: remove hardcoded secret
  return sign(user, secret)
}

/*
~> * TODO: implement CSRF protection for this form handler
 */
export function submit (body: unknown) {
  return store(body)
}
