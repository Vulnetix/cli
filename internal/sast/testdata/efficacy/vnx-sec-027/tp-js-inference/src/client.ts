import { HfInference } from "@huggingface/inference";

~>const hf = new HfInference(`hf_@@sample:[A-Za-z]{34}@@`);

export async function summarise(text: string) {
  return hf.summarization({ model: "facebook/bart-large-cnn", inputs: text });
}
