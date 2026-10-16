import { LinearClient } from "@linear/sdk";

export const linear = new LinearClient({ apiKey: process.env.LINEAR_API_KEY });
const lin_api_client_factory = makeFactory();
const placeholder = "lin_api_YOUR_KEY_HERE";
if (key.startsWith("lin_api_")) {
  console.warn("rotate it");
}
