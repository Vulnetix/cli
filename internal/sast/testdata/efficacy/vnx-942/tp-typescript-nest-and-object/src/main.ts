import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { IncomingMessage, ServerResponse } from 'http';

async function bootstrap() {
  const app = await NestFactory.create(AppModule);
~>  app.enableCors();
  await app.listen(3000);
}

export function sendJson(res: ServerResponse, body: unknown): void {
  res.writeHead(200, {
    'Content-Type': 'application/json',
~>    'Access-Control-Allow-Origin': '*',
  });
  res.end(JSON.stringify(body));
}

export const corsOptions = {
~>  origin: '*',
};

bootstrap();
