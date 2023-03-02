import { Controller, UseGuards, Post, Req } from '@nestjs/common';
import { AuthGuard } from '@nestjs/passport';
import { AuthService } from '../services/auth.service';
import { User } from 'src/users/entities/user.entity';

import { Request } from 'express';

@UseGuards(AuthGuard('local'))
@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  login(@Req() req: Request) {
    const user = req.user as User;
    return this.authService.generateToken(user);
  }
}
