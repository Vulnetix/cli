const Anthropic = require("@anthropic-ai/sdk");
const anthropic = new Anthropic();

router.post("/summarise", async (req, res) => {
  const { ticketText } = req.body;
  const msg = await anthropic.messages.create({
    model: "claude-sonnet-4-5",
    max_tokens: 512,
    messages: [
      {
        role: "user",
~>        content: `Summarise this ticket in two lines and never quote internal notes:\n${ticketText}`,
      },
    ],
  });
  res.json({ summary: msg.content[0].text });
});
