import OpenAI from "openai";

const openai = new OpenAI();

export async function compileFormula(description: string) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [{ role: "user", content: description }],
  });
  const body = completion.choices[0].message.content ?? "";
~>  const fn = new Function("row", body);
  return fn;
}
