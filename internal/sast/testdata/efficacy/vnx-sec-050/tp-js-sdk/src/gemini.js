import { GoogleGenerativeAI } from "@google/generative-ai";

const genAI = new GoogleGenerativeAI(
~>  'AIza@@sample:[A-Za-z0-9]{35}@@'
);
export const model = genAI.getGenerativeModel({ model: "gemini-pro" });
