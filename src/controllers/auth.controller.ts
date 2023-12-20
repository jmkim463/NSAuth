import { Body, Controller, Post } from '@nestjs/common';
import { AuthDto } from '../core/dtos/auth.dto';
import { User } from '../core/entities/user.entity';
import { ApiOperation, ApiTags } from '@nestjs/swagger';
import {
  ApiConflictResponse,
  ApiOkResponse,
  ApiUnauthorizedResponse,
} from '@nestjs/swagger/dist/decorators/api-response.decorator';
import { LoginDto } from '../core/dtos/login.dto';
import { UserService } from '../services/user/user.service';

@ApiTags('회원 인증')
@Controller('api/v1/auth')
export class AuthController {
  constructor(private userService: UserService) {}

  @ApiOperation({
    summary: '일반 회원 로그인',
    description:
      '일반 회원 로그인<br/>로그인 성공 시 access token, refresh token이 header로 전달된다.',
  })
  @ApiOkResponse({
    status: 200,
    description: '로그인에 성공한 경우',
    type: LoginDto,
  })
  @ApiUnauthorizedResponse({
    status: 401,
    description: '존재하지 않는 아이디의 경우</br>잘못된 비밀번호의 경우',
  })
  @Post('login')
  async login(@Body() authDto: AuthDto): Promise<LoginDto> {
    return await this.userService.login(authDto);
  }

  @ApiOkResponse({
    status: 200,
    description: '로그인에 성공한 경우',
  })
  @Post('login/auto')
  async loginWithToken(
    @Body('accessToken') accessToken: string,
  ): Promise<LoginDto> {
    return await this.userService.loginWithToken(accessToken);
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
    return this.userService.join(authDto);
  }
}
