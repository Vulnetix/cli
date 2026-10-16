import { GoogleGenerativeAI } from "@google/generative-ai";

const options = {
  retries: 3,
  region: "eu",
~>  token: "@@sample:AIza[0-9A-Za-z_-]{35}@@",
};

export const genAI = new GoogleGenerativeAI(options.token);
