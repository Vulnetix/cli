export async function chat(userMessage: string) {
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "You are a concise assistant." },
      { role: "user", content: `${userMessage}` },
    ],
  });
  return completion.choices[0].message.content;
}
