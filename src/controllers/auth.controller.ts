import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from '../services/auth/auth.service';
import { AuthDto } from '../core/dtos/auth.dto';
import { User } from '../core/entities/user.entity';
import { Response } from 'express';

@Controller('auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @Post('login')
  async login(
    @Body() authDto: AuthDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<any> {
    const user = await this.authService.validateUser(authDto);
    const accessToken = await this.authService.getAccessToken(user);
    const refreshToken = await this.authService.getRefreshToken(user);

    await this.authService.setCurrentRefreshToken(user._id, refreshToken);

    res.setHeader('Authorization', `Bearer ${accessToken} ${refreshToken}`);
    res.cookie('accessToken', accessToken, { httpOnly: true });
    res.cookie('refreshToken', refreshToken, { httpOnly: true });

    return user;
  }

  @Post('join')
  join(@Body() authDto: AuthDto): Promise<User> {
    return this.authService.join(authDto);
  }
}
