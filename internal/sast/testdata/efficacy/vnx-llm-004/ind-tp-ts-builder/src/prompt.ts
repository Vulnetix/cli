export function buildSystemPrompt (userName?: string) {
~>  const greeting = userName ? `\nThe customer you are chatting with is ${userName}.` : '';
  return `You are a helpful shop assistant.${greeting}`;
}
