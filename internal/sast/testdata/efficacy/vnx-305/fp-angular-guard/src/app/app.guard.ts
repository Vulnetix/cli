import { Injectable } from '@angular/core';
import { CanActivate } from '@angular/router';

@Injectable()
export class LoginGuard implements CanActivate {
  canActivate() {
    const token = localStorage.getItem('token');
    if (token) {
      return true;
    }
    return false;
  }
}
