import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document } from 'mongoose';
import * as bcrypt from 'bcrypt';

@Schema()
export class User {
  @Prop()
  username: string;

  @Prop()
  password: string;

  @Prop()
  nickname: string;

  @Prop()
  createAt: Date;

  @Prop()
  updateAt: Date;

  async validatePassword(password: string): Promise<boolean> {
    return await bcrypt.compare(password, this.password);
  }
}
export type UserDocument = User & Document;
export const UserSchema = SchemaFactory.createForClass(User);
