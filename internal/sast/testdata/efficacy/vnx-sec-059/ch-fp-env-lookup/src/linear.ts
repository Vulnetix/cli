import { LinearClient } from "@linear/sdk";

export const linear = new LinearClient({ apiKey: process.env.LINEAR_API_KEY });
