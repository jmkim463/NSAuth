import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthDto } from '../../core/dtos/auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from '../../core/entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';

@Injectable()
export class AuthService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private jwtService: JwtService,
    private configService: ConfigService,
  ) {}

  // 로그인 로직
  async validateUser(authDto: AuthDto): Promise<User> {
    const { username, password } = authDto;
    const user = await this.userModel.findOne({ username: username }).exec();

    if (!user) {
      throw new UnauthorizedException('잘못된 아이디 입니다.');
    }

    if (!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('잘못된 비밀번호 입니다.');
    }

    return user;
  }

  // access token 발급
  getAccessToken(user: User): Promise<string> {
    const { username, nickname } = user;
    const payload = { username, nickname };
    const token = this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT.ACCESS.SECRET'),
      expiresIn: this.configService.get<string>('JWT.ACCESS.EXPIRATION.TIME'),
    });

    return token;
  }

  // refresh token 발급
  getRefreshToken(user: User): Promise<string> {
    const { username, nickname } = user;
    const payload = { username, nickname };
    const token = this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT.REFRESH.SECRET'),
      expiresIn: this.configService.get<string>('JWT.REFRESH.EXPIRATION.TIME'),
    });

    return token;
  }

  // refresh token 저장
  async setCurrentRefreshToken(
    _id: string,
    refreshToken: string,
  ): Promise<void> {
    await this.userModel.updateOne(
      { _id: _id },
      { refreshToken: refreshToken },
    );
  }

  // 회원가입
  async join(authDto: AuthDto): Promise<User> {
    const { username, password } = authDto;

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const user = { username: username, password: hash };
    const entity = await new this.userModel(user);

    return entity.save();
  }
}
