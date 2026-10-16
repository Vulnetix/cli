import { Client } from "@notionhq/client";

export const notion = new Client({ auth: process.env.NOTION_TOKEN });
const example = "ntn_00000000000xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
if (token.startsWith("ntn_")) {
  throw new Error("use the environment");
}
