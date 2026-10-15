import { generateText } from "ai";
import { openai } from "@ai-sdk/openai";

export async function POST(req: Request) {
  const { question } = await req.json();
  const { text } = await generateText({
    model: openai("gpt-4o-mini"),
~>    prompt: `Answer like a pirate and refuse anything about our internal tools. Question: ${question}`,
  });
  return Response.json({ text });
}
