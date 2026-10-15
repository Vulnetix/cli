import { Client } from "@notionhq/client";

export const notion = new Client({
~>  auth: "ntn_@@sample:[0-9]{11}@@@@sample:[A-Za-z0-9]{35}@@",
});
