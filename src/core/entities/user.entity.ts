import { Prop, Schema, SchemaFactory } from '@nestjs/mongoose';
import { Document, Types } from 'mongoose';

@Schema()
export class User {
  @Prop({ type: Types.ObjectId, auto: true })
  _id: string;

  @Prop()
  username: string;

  @Prop()
  password: string;

  @Prop()
  nickname: string;

  @Prop()
  createAt: Date;

  @Prop({
    required: false,
    default: null,
  })
  refreshToken: string;

  @Prop({
    required: false,
    default: null,
  })
  refreshTokenExp: Date;
}
export type UserDocument = User & Document;
export const UserSchema = SchemaFactory.createForClass(User);
