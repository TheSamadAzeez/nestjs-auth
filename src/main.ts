import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import helmet from 'helmet';
import cookieParser from 'cookie-parser';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
  app.enableCors({
    origin: process.env.FRONTEND_URL, //TODO: use config service
    credentials: true, // allows cookies cross-origin
  });

  app.use(helmet()); // sets secure HTTP headers
  app.use(cookieParser()); // needed to read req.cookies

  await app.listen(process.env.PORT ?? 3000);
}
bootstrap();
