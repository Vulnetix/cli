import { logger } from "./logger";

export function book(traveller: Traveller): string {
~>  logger.info(`booking for ${traveller.name}, passport ${traveller.passport}`);
~>  console.debug("traveller document", { passportNumber: traveller.passportNumber, nationality: traveller.nationality });
  return reserve(traveller);
}
