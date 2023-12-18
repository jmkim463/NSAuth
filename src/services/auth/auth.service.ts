import { Injectable, UnauthorizedException } from '@nestjs/common';
import { AuthDto } from '../../core/dtos/auth.dto';
import { InjectModel } from '@nestjs/mongoose';
import { User, UserDocument } from '../../core/entities/user.entity';
import { Model } from 'mongoose';
import * as bcrypt from 'bcrypt';

@Injectable()
export class AuthService {
  constructor(@InjectModel(User.name) private userModel: Model<UserDocument>) {}

  async login(authDto: AuthDto): Promise<User> {
    const { username, password } = authDto;
    const user = await this.userModel.findOne({ username: username }).exec();

    if (!user) {
      throw new UnauthorizedException('잘못된 아이디 입니다.');
    }

    if (!user.validatePassword(password)) {
      throw new UnauthorizedException('잘못된 비밀번호 입니다.');
    }

    return user;
  }

  async join(authDto: AuthDto): Promise<User> {
    const { username, password } = authDto;

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(password, salt);

    const user = { username: username, password: hash };
    const entity = await new this.userModel(user);

    return entity.save();
  }
}
