import { Injectable } from '@nestjs/common';
import * as bcrypt from 'bcrypt';

import { UsersService } from '../../users/services/users.service';

@Injectable()
export class AuthService {
  constructor(private usersService: UsersService) {}

  async validateUser(email: string, password: string) {
    const user = this.usersService.findByEmail(email);
    const isAuth = bcrypt.compare(password, user.password);
    if (user && isAuth) {
      return user;
    }
    return null;
  }
}
