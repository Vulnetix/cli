import { Client } from "@notionhq/client";

~>const notion = new Client({ auth: "ntn_@@sample:[0-9]{11}@@@@sample:[A-Za-z0-9]{35}@@" });
export default notion;
