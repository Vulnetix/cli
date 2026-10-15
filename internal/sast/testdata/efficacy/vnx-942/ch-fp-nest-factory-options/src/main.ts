import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';

async function bootstrap() {
  const app = await NestFactory.create(AppModule, { cors: { origin: ['https://app.example.com'], credentials: true } });
  const flags = { cors: true }; // feature flags, not the server
  await app.listen(3000);
}
bootstrap();
