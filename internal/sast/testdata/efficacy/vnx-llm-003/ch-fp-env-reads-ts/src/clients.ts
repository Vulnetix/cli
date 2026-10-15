import OpenAI from "openai";
import { ChatAnthropic } from "@langchain/anthropic";

export const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });
export const claude = new ChatAnthropic({ anthropicApiKey: config.get("anthropic.apiKey"), model: "claude-sonnet-4-5" });
const OPENAI_MODEL = "@@sample:g[p]t[-][4]o[-][m]in[i][-]2[0]24[-]07[-]18@@";
