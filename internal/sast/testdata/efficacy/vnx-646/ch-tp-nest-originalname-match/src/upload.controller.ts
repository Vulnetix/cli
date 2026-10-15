import { BadRequestException, Controller, Post, UploadedFile, UseInterceptors } from "@nestjs/common";
import { FileInterceptor } from "@nestjs/platform-express";

@Controller("docs")
export class UploadController {
  @Post()
  @UseInterceptors(FileInterceptor("file"))
  upload(@UploadedFile() file: Express.Multer.File) {
~>    if (!file.originalname.match(/\.(pdf|txt)$/i)) {
      throw new BadRequestException("pdf or txt only");
    }
    return { name: file.filename };
  }
}
