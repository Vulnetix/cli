import Anthropic from '@anthropic-ai/sdk';
import { execSync } from 'node:child_process';

const anthropic = new Anthropic();

export async function runFix(errorLog: string): Promise<string> {
  const msg = await anthropic.messages.create({
    model: 'claude-sonnet-4-5',
    max_tokens: 512,
    messages: [{ role: 'user', content: `Suggest one shell command to fix:\n${errorLog}` }],
  });
  const block = msg.content[0];
  const command: string = msg.content[0].text.trim();
~>  return execSync(command, { encoding: 'utf8' });
}
