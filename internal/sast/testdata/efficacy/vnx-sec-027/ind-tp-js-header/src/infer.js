const res = await fetch("https://api-inference.huggingface.co/models/gpt2", {
  method: "POST",
  headers: {
~>    Authorization: `Bearer hf_@@sample:[A-Za-z0-9]{34}@@`,
  },
  body: JSON.stringify({ inputs: "hi" }),
});
