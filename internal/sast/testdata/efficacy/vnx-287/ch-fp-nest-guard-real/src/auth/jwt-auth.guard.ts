import { CanActivate, ExecutionContext, Injectable, UnauthorizedException } from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class JwtAuthGuard implements CanActivate {
  constructor(private readonly jwt: JwtService) {}

  canActivate(context: ExecutionContext): boolean {
    const req = context.switchToHttp().getRequest();
    const header = req.headers.authorization ?? '';
    try {
      req.user = this.jwt.verify(header.replace(/^Bearer /, ''));
      return true;
    } catch {
      throw new UnauthorizedException();
    }
  }
}

@Injectable()
export class PublicRouteGuard implements CanActivate {
  canActivate(): boolean {
    return true;
  }
}
