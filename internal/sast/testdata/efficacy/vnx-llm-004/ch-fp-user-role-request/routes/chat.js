router.post("/chat", async (req, res) => {
  const { message } = req.body;
  const completion = await openai.chat.completions.create({
    model: "gpt-4o-mini",
    messages: [
      { role: "system", content: "You are a concise assistant for Acme." },
      { role: "user", content: message },
    ],
  });
  res.json(completion.choices[0].message);
});
