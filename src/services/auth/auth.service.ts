import { BadRequestException, Injectable } from '@nestjs/common';
import { User } from '../../core/entities/user.entity';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  // access token 발급
  getAccessToken(user: User): Promise<string> {
    const { username, _id } = user;
    const payload = { username, _id };
    const token = this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT.ACCESS.SECRET'),
      expiresIn:
        this.configService.get<number>('JWT.ACCESS.EXPIRATION.DAY') *
        24 *
        60 *
        60,
    });

    return token;
  }

  // refresh token 발급
  getRefreshToken(user: User): Promise<string> {
    const { username, _id } = user;
    const payload = { username, _id };
    const token = this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT.REFRESH.SECRET'),
      expiresIn:
        this.configService.get<number>('JWT.REFRESH.EXPIRATION.DAY') *
        24 *
        60 *
        60,
    });

    return token;
  }

  // refresh token 만료 기간
  getRefreshTokenExp(): Date {
    const now = new Date();
    const refreshTokenExp = new Date(
      now.getTime() +
        this.configService.get<number>('JWT.REFRESH.EXPIRATION.DAY') *
          24 *
          60 *
          60,
    );
    return refreshTokenExp;
  }

  async verifyToken(token: string): Promise<string> {
    try {
      const _id = await this.jwtService.verifyAsync(token.toString(), {
        secret: this.configService.get<string>('JWT.ACCESS.SECRET'),
      });

      return _id;
    } catch (err) {
      throw new BadRequestException();
    }
  }
}
