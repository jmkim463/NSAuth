import { Body, Controller, Post, Res } from '@nestjs/common';
import { AuthService } from '../services/auth/auth.service';
import { AuthDto } from '../core/dtos/auth.dto';
import { User } from '../core/entities/user.entity';
import { Response } from 'express';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  ApiConflictResponse, ApiFoundResponse,
  ApiOkResponse,
  ApiUnauthorizedResponse
} from "@nestjs/swagger/dist/decorators/api-response.decorator";
import { UserDto } from '../core/dtos/user.dto';

@ApiTags('회원 인증')
@Controller('api/v1/auth')
export class AuthController {
  constructor(private authService: AuthService) {}

  @ApiOperation({
    summary: '일반 회원 로그인',
    description:
      '일반 회원 로그인<br/>로그인 성공 시 access token, refresh token이 header로 전달된다.',
  })
  @ApiOkResponse({
    status: 200,
    description: '로그인에 성공한 경우',
    type: UserDto,
  })
  @ApiUnauthorizedResponse({
    status: 401,
    description: '존재하지 않는 아이디의 경우</br>잘못된 비밀번호의 경우',
  })
  @Post('login')
  async login(
    @Body() authDto: AuthDto,
    @Res({ passthrough: true }) res: Response,
  ): Promise<any> {
    const user = await this.authService.validateUser(authDto);
    const accessToken = await this.authService.getAccessToken(user);
    const refreshToken = await this.authService.getRefreshToken(user);

    const { _id, nickname, createAt } = user;

    await this.authService.setCurrentRefreshToken(_id, refreshToken);

    // res.setHeader('Authorization', `Bearer ${accessToken} ${refreshToken}`);

    return { nickname, createAt, accessToken, refreshToken };
  }

  @ApiOkResponse({
    status: 200,
    description: '로그인에 성공한 경우',
  })
  @Post('login/auto')
  async loginWithToken(@Body('accessToken') accessToken: string, @Body('refreshToken') refreshToken: string) {
    const user = await this.authService.validateUserWithToken(accessToken);
    // const { nickname, createAt } = user;

    return user;
  }

  @ApiOperation({ summary: '일반 회원 회원가입' })
  @ApiOkResponse({
    status: 200,
    description: '회원가입에 성공한 경우',
  })
  @ApiConflictResponse({
    status: 409,
    description: '중복된 id일 경우',
  })
  @Post('join')
  join(@Body() authDto: AuthDto): Promise<User> {
    return this.authService.join(authDto);
  }
}
