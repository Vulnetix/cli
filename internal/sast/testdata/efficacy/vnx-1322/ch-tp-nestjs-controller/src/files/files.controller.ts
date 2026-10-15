import { Controller, Get, Param, Res } from '@nestjs/common';
import { Response } from 'express';
import * as fs from 'fs';

@Controller('files')
export class FilesController {
  @Get(':name')
  download(@Param('name') name: string, @Res() res: Response) {
~>    const body = fs.readFileSync(`/srv/files/${name}`);
    res.send(body);
  }
}
