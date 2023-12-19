import { ApiProperty } from '@nestjs/swagger';

export class UserDto {
  @ApiProperty({
    example: '닉네임',
    description: '회원 닉네임',
  })
  nickname: string;

  @ApiProperty({
    example: '가입 날짜',
  })
  createAt: Date;
}
