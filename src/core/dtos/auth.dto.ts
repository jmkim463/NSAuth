import { IsNotEmpty } from '@nestjs/class-validator';
import { ApiProperty } from '@nestjs/swagger';

export class AuthDto {
  @ApiProperty({
    example: '아이디',
    description: '회원 아이디',
    required: true,
  })
  @IsNotEmpty()
  username: string;

  @ApiProperty({
    example: '비밀번호',
    description: '회원 비밀번호',
    required: true,
  })
  @IsNotEmpty()
  password: string;
}
