import { Module, NestModule } from '@nestjs/common';
import { AuthController } from './controllers/auth.controller';
import { ConfigModule, ConfigService } from '@nestjs/config';
import { MongooseModule } from '@nestjs/mongoose';
import { AuthModule } from './services/auth/auth.module';
import { MiddlewareConsumer } from '@nestjs/common/interfaces/middleware/middleware-consumer.interface';
import * as mongoose from 'mongoose';
import { PassportModule } from '@nestjs/passport';
import { UserModule } from './services/user/user.module';
import { HttpModule } from '@nestjs/axios';

@Module({
  imports: [
    ConfigModule.forRoot({
      isGlobal: true,
      envFilePath: '.local.env',
    }),
    MongooseModule.forRootAsync({
      imports: [ConfigModule],
      useFactory: async (config: ConfigService) => ({
        uri: `mongodb://${config.get<string>(
          'MONGODB.URL',
        )}:${config.get<string>('MONGODB.PORT')}/NSAuth`,
      }),
      inject: [ConfigService],
    }),
    HttpModule,
    PassportModule,
    AuthModule,
    UserModule,
  ],
  controllers: [AuthController],
})
export class AppModule implements NestModule {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  configure(consumer: MiddlewareConsumer) {
    mongoose.set('debug', true);
  }
}
