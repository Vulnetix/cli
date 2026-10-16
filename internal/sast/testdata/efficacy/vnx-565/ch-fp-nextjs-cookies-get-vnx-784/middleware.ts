import { NextRequest, NextResponse } from 'next/server';

export function middleware(request: NextRequest) {
  // Reported by VNX-784 (a security decision on a cookie), not by this rule.
  if (request.cookies.get('isAdmin')?.value === 'true') {
    return NextResponse.next();
  }
  return NextResponse.redirect(new URL('/login', request.url));
}
