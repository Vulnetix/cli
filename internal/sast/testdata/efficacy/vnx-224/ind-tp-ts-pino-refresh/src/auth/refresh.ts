import pino from "pino";

const logger = pino();

export async function rotate(userId: string, refreshToken: string): Promise<string> {
  const next = await issueRefresh(userId);
~>  logger.warn(`rotating ${Buffer.from(refreshToken).toString("base64")} for ${userId}`);
  return next;
}
