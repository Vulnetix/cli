export function issue(res: Response, jwt: string) {
  // Reported by VNX-NODE-029 (a Node.js cookie without HttpOnly), not by this rule.
  res.cookie('access_token', jwt, {
    // Reported by VNX-614 (a cookie without Secure), not by this rule.
    secure: false,
    sameSite: 'lax',
  });
}
