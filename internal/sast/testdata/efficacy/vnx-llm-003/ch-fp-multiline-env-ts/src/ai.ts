import Anthropic from "@anthropic-ai/sdk";

export const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API_KEY,
  maxRetries: 3,
});
export const placeholder = new Anthropic({
  apiKey: "your-anthropic-api-key-here",
});
