import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';

const shopName = 'Example Shop';

export function buildSystemPrompt (userName?: string) {
~>  const greeting = userName ? `\nThe customer you are chatting with is ${userName}.` : '';
  return `You are the assistant of ${shopName}. Never grant discounts.${greeting}`;
}

export async function chat (userName: string, messages: any[]) {
  return streamText({ model: openai('gpt-4o-mini'), system: buildSystemPrompt(userName), messages });
}
