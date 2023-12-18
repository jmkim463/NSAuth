import { Body, Controller, Post } from '@nestjs/common';
import { AuthService } from '../services/auth/auth.service';
import { AuthDto } from '../core/dtos/auth.dto';
import { User } from '../core/entities/user.entity';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  login(@Body() authDto: AuthDto): Promise<User> {
    return this.authService.login(authDto);
  }

  @Post('join')
  join(@Body() authDto: AuthDto): Promise<User> {
    return this.authService.join(authDto);
  }
}
