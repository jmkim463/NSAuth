import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { ConfigService } from '@nestjs/config';
import { Logger, ValidationPipe } from '@nestjs/common';
import { DocumentBuilder, SwaggerModule } from '@nestjs/swagger';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  const configService = app.get(ConfigService);
  const port = configService.get('SERVER.PORT');
  const logger = new Logger();

  const swagger = new DocumentBuilder()
    .setTitle('NSAuth')
    .setDescription('NSAuth 인증 서버')
    .setVersion(configService.get<string>('SERVER.VERSION'))
    .addTag('swagger')
    .build();
  const document = SwaggerModule.createDocument(app, swagger);
  SwaggerModule.setup('swagger', app, document);

  app.useGlobalPipes(new ValidationPipe());

  await app.listen(port);

  logger.log(`${port} START ^_____^ `);
}
bootstrap();
