import { IsNotEmpty } from '@nestjs/class-validator';

export class AuthDto {
  @IsNotEmpty()
  username: string;

  @IsNotEmpty()
  password: string;
}
