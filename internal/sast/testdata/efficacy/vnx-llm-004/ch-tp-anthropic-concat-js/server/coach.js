const Anthropic = require("@anthropic-ai/sdk");
const client = new Anthropic();

app.post("/coach", async (req, res) => {
  const goal = req.body.goal;
  const msg = await client.messages.create({
    model: "claude-sonnet-4-5",
    max_tokens: 800,
~>    system: "You are a fitness coach. The user's goal is: " + goal + ". Do not give medical advice.",
    messages: [{ role: "user", content: req.body.question }],
  });
  res.json(msg.content);
});
