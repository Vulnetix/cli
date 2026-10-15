import OpenAI from "openai";

export const openai = new OpenAI({
~>  apiKey: "@@sample:[A-Za-z0-9]{24}[0-9]{4}[A-Za-z]{8}@@",
  organization: "org-acme",
});
