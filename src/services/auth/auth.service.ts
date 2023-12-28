import { HttpException, Injectable } from '@nestjs/common';
import { User } from '../../core/entities/user.entity';
import { JwtService, TokenExpiredError } from '@nestjs/jwt';
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
      expiresIn: this.configService.get<number>('JWT.ACCESS.EXPIRATION'),
    });

    return token;
  }

  // refresh token 발급
  getRefreshToken(user: User): Promise<string> {
    const { username, _id } = user;
    const payload = { username, _id };
    const token = this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT.REFRESH.SECRET'),
      expiresIn: this.configService.get<number>('JWT.REFRESH.EXPIRATION'),
    });

    return token;
  }

  async verifyToken(
    accessToken: string,
    refreshToken: string,
  ): Promise<string> {
    try {
      return await this.verifyAccessToken(accessToken);
    } catch (err) {
      if (err instanceof TokenExpiredError) {
        return await this.verifyRefreshToken(refreshToken);
      } else {
        throw new HttpException('일치하지 않은 accessToken', 401);
      }
    }
  }

  private async verifyAccessToken(accessToken: string): Promise<string> {
    const { _id } = await this.jwtService.verifyAsync(accessToken.toString(), {
      secret: this.configService.get<string>('JWT.ACCESS.SECRET'),
    });
    return _id;
  }

  private async verifyRefreshToken(refreshToken: string): Promise<string> {
    try {
      const { _id } = await this.jwtService.verifyAsync(
        refreshToken.toString(),
        {
          secret: this.configService.get<string>('JWT.ACCESS.SECRET'),
        },
      );
      return _id;
    } catch (err) {
      if (err instanceof TokenExpiredError) {
        throw new HttpException('만료된 refreshToken 입니다.', 410);
      } else {
        throw new HttpException('일치하지 않은 refreshToken', 401);
      }
    }
  }
}
