import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthDto } from '../../core/dtos/auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from '../../core/entities/user.entity';
import mongoose, { Model } from 'mongoose';
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

  // refresh token 저장
  async setCurrentRefreshToken(
    _id: string,
    refreshToken: string,
  ): Promise<void> {
    const token = this.setHashedRefreshToken(refreshToken);
    const exp = this.getRefreshTokenExp();

    await this.userModel.updateOne(
      { _id: _id },
      { refreshToken: token, refreshExp: exp },
    );
  }

  // refresh token 재 암호화
  private setHashedRefreshToken(refreshToken: string) {
    const token = bcrypt.hashSync(refreshToken, 10);
    return token;
  }

  // refresh token 만료 기간
  private getRefreshTokenExp(): Date {
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

  // 토큰을 이용한 로그인 !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
  async validateUserWithToken(accessToken: string): Promise<User> {
    const verify = await this.jwtService.verifyAsync(accessToken.toString(), {
      secret: this.configService.get<string>('JWT.ACCESS.SECRET'),
    });

    const { _id } = verify;
    const user = await this.userModel.findOne({
      _id: new mongoose.Types.ObjectId(_id),
    });
    console.log(user);

    return user;
  }

  // 회원가입
  async join(authDto: AuthDto): Promise<User> {
    const { username, password } = authDto;

    if (await this.isHaveSameUsername(username)) {
      throw new ConflictException('중복된 아이디 입니다.');
    }

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const user = { username: username, password: hash };
    const entity = await new this.userModel(user);

    return entity.save();
  }

  private async isHaveSameUsername(username: string): Promise<boolean> {
    const user = await this.userModel.findOne({ username: username });
    return user !== null;
  }
}
