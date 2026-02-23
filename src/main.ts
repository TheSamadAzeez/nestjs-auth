import { ValidationPipe } from '@nestjs/common';
import { NestFactory } from '@nestjs/core';
import cookieParser from 'cookie-parser';
import helmet from 'helmet';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.useGlobalPipes(
    new ValidationPipe({
      whitelist: true, // remove any properties that are not in the dto
      forbidNonWhitelisted: true, // throw an error if a property is not in the dto
      transform: true, // transform the request body to the dto type
    }),
  );
  app.enableCors({
    origin: process.env.FRONTEND_URL,
    credentials: true, // allows cookies cross-origin
  });

  app.use(helmet()); // sets secure HTTP headers
  app.use(cookieParser()); // needed to read req.cookies

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
