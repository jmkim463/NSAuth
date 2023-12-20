import { ApiProperty } from '@nestjs/swagger';

export class LoginDto {
  @ApiProperty({
    example: '닉네임',
    description: '회원 닉네임',
  })
  nickname: string;

  @ApiProperty({
    example: '가입 날짜',
  })
  createAt: Date;

  accessToken?: string;

  refreshToken?: string;
}
