import Anthropic from '@anthropic-ai/sdk';
import Groq from 'groq-sdk';

~>export const COHERE_API_KEY = "@@sample:[A-Za-z0-9]{40}@@";
~>const groq = new Groq({ apiKey: '@@sample:[A-Za-z0-9]{48}@@' });
export const anthropic = new Anthropic({
~>  apiKey: "sk-ant-api03-@@sample:[A-Za-z0-9_-]{93}@@AA",
});
~>const mistralApiKey = `@@sample:[A-Za-z0-9]{32}@@`;
