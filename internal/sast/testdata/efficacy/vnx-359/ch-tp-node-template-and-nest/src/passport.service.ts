import { Injectable, Logger } from "@nestjs/common";

@Injectable()
export class PassportService {
  private readonly logger = new Logger(PassportService.name);

  save(dto: { passportNumber: string; nationalId: string }) {
~>    this.logger.log(`Saving passport ${dto.passportNumber}`);
~>    console.info("national id", dto.nationalId);
    return dto;
  }
}
