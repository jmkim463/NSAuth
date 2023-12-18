import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { Logger, ValidationPipe } from '@nestjs/common';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get('SERVER.PORT');
  const logger = new Logger();

  app.useGlobalPipes(new ValidationPipe());
  await app.listen(port);

  logger.log(`${port} START ^_____^ `);
}
bootstrap();
