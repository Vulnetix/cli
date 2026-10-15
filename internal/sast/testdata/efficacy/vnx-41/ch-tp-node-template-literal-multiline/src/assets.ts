import { promises as fs } from "fs";

const ASSET_DIR = "/opt/app/assets";

export async function readAsset(rel: string): Promise<Buffer> {
  const file = `${ASSET_DIR}/${rel}`;
  if (
~>    !file.startsWith(ASSET_DIR)
  ) {
    throw new Error("forbidden");
  }
  return fs.readFile(file);
}
