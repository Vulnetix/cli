import { Controller, Get, Param } from '@nestjs/common';
import { DataSource } from 'typeorm';

@Controller('users')
export class UsersController {
  constructor(private readonly dataSource: DataSource) {}

  @Get(':id')
  async find(@Param('id') id: string) {
~>    return this.dataSource.query('SELECT * FROM users WHERE id = $1', [id]);
  }
}
