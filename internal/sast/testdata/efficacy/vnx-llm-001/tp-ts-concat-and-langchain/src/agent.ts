import { ChatOpenAI } from '@langchain/openai';
import type { Request, Response } from 'express';

const model = new ChatOpenAI({ model: 'gpt-4o-mini' });

export async function review(req: Request, res: Response) {
  const userInput: string = req.body.code;
~>  const result = await model.invoke('Review this code and list security issues. Code: ' + userInput);
  res.json({ review: result.content });
}
