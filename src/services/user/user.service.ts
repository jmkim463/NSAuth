import {
  ConflictException,
  Injectable,
  UnauthorizedException,
} from '@nestjs/common';
import { AuthDto } from '../../core/dtos/auth.dto';
import { User, UserDocument } from '../../core/entities/user.entity';
import * as bcrypt from 'bcrypt';
import { InjectModel } from '@nestjs/mongoose';
import mongoose, { Model } from 'mongoose';
import { AuthService } from '../auth/auth.service';
import { LoginDto } from '../../core/dtos/login.dto';
@Injectable()
export class UserService {
  constructor(
    @InjectModel(User.name) private userModel: Model<UserDocument>,
    private authService: AuthService,
  ) {}

  // 로그인 로직
  async login(authDto: AuthDto): Promise<LoginDto> {
    const { username, password } = authDto;
    const user = await this.userModel.findOne({ username: username }).exec();

    if (!user) {
      throw new UnauthorizedException('잘못된 아이디 입니다.');
    }

    if (!bcrypt.compareSync(password, user.password)) {
      throw new UnauthorizedException('잘못된 비밀번호 입니다.');
    }

    const { _id, nickname, createAt } = user;
    const accessToken = await this.authService.getAccessToken(user);
    const refreshToken = await this.authService.getRefreshToken(user);

    const hash = await bcrypt.hash(refreshToken, 10);
    const exp = this.authService.getRefreshTokenExp();

    await this.userModel.updateOne(
      { _id: _id },
      { refreshToken: hash, refreshExp: exp },
    );

    const loginDto: LoginDto = {
      nickname,
      createAt,
      accessToken,
      refreshToken,
    };

    return loginDto;
  }

  // 토큰을 이용한 로그인
  async loginWithToken(accessToken: string): Promise<LoginDto> {
    const _id = await this.authService.verifyToken(accessToken);
    const user = await this.userModel.findOne({
      _id: new mongoose.Types.ObjectId(_id),
    });

    const { nickname, createAt } = user;
    const loginDto: LoginDto = {
      nickname,
      createAt,
    };

    return loginDto;
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
